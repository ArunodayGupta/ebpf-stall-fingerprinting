"""
eBPF Event Collector for Linux Kernel Observability.

Interfaces with BCC to:
- Compile and inject the kernel-side eBPF probes
- Filter telemetry to monitored target PIDs
- Stream perf buffer records to the structured event writer
- Track buffer drops, probe attachment status, and diagnostics
"""

import sys
import os
import time
import threading
import logging
import ctypes
from pathlib import Path
from typing import List, Optional, Dict, Any, Union

from stall_fingerprint.bpf_program import BPF_C_SOURCE, KernelEventCStruct, SYSCALL_ID_TO_NAME
from stall_fingerprint.event_schema import (
    EventType,
    BaseEvent,
    SyscallEvent,
    BlockEvent,
    SchedEvent,
    DiagnosticEvent,
    DroppedEventStats,
    EventWriter,
)

logger = logging.getLogger("stall_fingerprint.collector")

class BPFCollectorError(Exception):
    """Raised when the eBPF collector cannot initialize or attach probes."""
    pass

class BPFCollector:
    """
    Manages the lifecycle of kernel eBPF probes and streams events to disk.
    """

    def __init__(
        self,
        output_path: Union[str, Path],
        target_pids: Optional[List[int]] = None,
        perf_page_cnt: int = 64,
        poll_timeout_ms: int = 100,
    ):
        self.output_path = Path(output_path)
        self.target_pids = list(target_pids or [])
        self.perf_page_cnt = perf_page_cnt
        self.poll_timeout_ms = poll_timeout_ms

        self.bpf_instance = None
        self.writer: Optional[EventWriter] = None
        self._thread: Optional[threading.Thread] = None
        self._stop_requested = threading.Event()

        self.total_events_emitted = 0
        self.total_events_lost = 0
        self.probe_status: Dict[str, str] = {}
        self.is_active = False

    def add_target_pid(self, pid: int):
        """Dynamically add a PID to the target filter map."""
        if pid not in self.target_pids:
            self.target_pids.append(pid)
        if self.bpf_instance is not None:
            try:
                target_map = self.bpf_instance["target_pids"]
                target_map[ctypes.c_uint32(pid)] = ctypes.c_uint8(1)
                logger.info(f"Registered PID {pid} in in-kernel filter map.")
            except Exception as e:
                logger.warning(f"Failed to add PID {pid} to in-kernel filter map: {e}")

    def initialize_bpf(self):
        """Compile BPF source and attach probes via BCC."""
        try:
            from bcc import BPF
        except ImportError as e:
            raise BPFCollectorError(
                f"BCC is not available in current environment: {e}. "
                "Ensure bpfcc-tools and python3-bpfcc are installed on Linux."
            )

        if os.name == "posix" and os.geteuid() != 0:
            raise BPFCollectorError(
                "Root privileges (EUID 0) required to load eBPF tracing programs. "
                "Run with sudo or appropriate capabilities."
            )

        logger.info("Compiling and verifying eBPF kernel program via BCC...")
        try:
            self.bpf_instance = BPF(text=BPF_C_SOURCE)
        except Exception as e:
            raise BPFCollectorError(f"Failed to compile/load eBPF program: {e}")

        # Populate target PIDs
        target_map = self.bpf_instance["target_pids"]
        for pid in self.target_pids:
            target_map[ctypes.c_uint32(pid)] = ctypes.c_uint8(1)

        self.probe_status["compilation"] = "SUCCESS"
        logger.info("eBPF probes verified and loaded into kernel.")

    def _event_callback(self, cpu: int, data: Any, size: int):
        """BCC callback invoked when an event arrives from perf ring buffer."""
        try:
            c_event = ctypes.cast(data, ctypes.POINTER(KernelEventCStruct)).contents
            ev_type_id = c_event.event_type
            ts = c_event.timestamp_ns
            comm = c_event.comm.decode("utf-8", errors="ignore").strip()

            if ev_type_id == 1:  # EV_SYSCALL_COMPLETE
                name = SYSCALL_ID_TO_NAME.get(c_event.syscall_id, f"sys_{c_event.syscall_id}")
                event = SyscallEvent(
                    event_type=EventType.SYSCALL_COMPLETE.value,
                    timestamp_ns=ts,
                    pid=c_event.pid,
                    tid=c_event.tid,
                    comm=comm,
                    syscall_name=name,
                    syscall_id=c_event.syscall_id,
                    duration_ns=c_event.duration_ns,
                    ret=c_event.ret,
                )
            elif ev_type_id in (2, 3):  # BLOCK_RQ_ISSUE / COMPLETE
                rwbs = c_event.rwbs.decode("utf-8", errors="ignore").strip()
                t_str = EventType.BLOCK_RQ_ISSUE.value if ev_type_id == 2 else EventType.BLOCK_RQ_COMPLETE.value
                event = BlockEvent(
                    event_type=t_str,
                    timestamp_ns=ts,
                    dev=c_event.dev,
                    sector=c_event.sector,
                    nr_sector=c_event.nr_sector,
                    bytes_count=c_event.bytes_count,
                    rwbs=rwbs,
                    pid=c_event.pid,
                    comm=comm,
                    error=c_event.error,
                )
            elif ev_type_id in (4, 5):  # SCHED_WAKEUP / SCHED_SWITCH
                t_str = EventType.SCHED_WAKEUP.value if ev_type_id == 4 else EventType.SCHED_SWITCH.value
                event = SchedEvent(
                    event_type=t_str,
                    timestamp_ns=ts,
                    prev_pid=c_event.prev_pid,
                    next_pid=c_event.next_pid,
                    prev_state=c_event.prev_state,
                    target_pid=c_event.pid,
                    is_on_cpu=bool(c_event.is_on_cpu),
                    runnable_delay_ns=c_event.runnable_delay_ns,
                )
            else:
                event = BaseEvent(
                    event_type=f"UNKNOWN_{ev_type_id}",
                    timestamp_ns=ts,
                )

            if self.writer is not None:
                self.writer.write_event(event)
                self.total_events_emitted += 1

        except Exception as e:
            logger.error(f"Error decoding BPF event: {e}")

    def _lost_callback(self, lost_count: int):
        """BCC callback invoked when perf buffer drops events due to overflow."""
        self.total_events_lost += lost_count
        logger.warning(f"Perf buffer dropped {lost_count} events (total lost: {self.total_events_lost})")
        if self.writer is not None:
            self.writer.write_event(
                DiagnosticEvent(
                    event_type=EventType.COLLECTOR_DIAGNOSTIC.value,
                    timestamp_ns=time.monotonic_ns(),
                    subsystem="perf_buffer",
                    status="WARNING",
                    message=f"Perf buffer event drop detected: {lost_count} lost",
                    details={"lost_count": lost_count, "cumulative_lost": self.total_events_lost},
                )
            )

    def _polling_loop(self):
        """Background thread polling BCC perf buffer."""
        try:
            self.bpf_instance["events"].open_perf_buffer(
                self._event_callback,
                lost_cb=self._lost_callback,
                page_cnt=self.perf_page_cnt,
            )
            while not self._stop_requested.is_set():
                # Poll perf buffer with timeout
                self.bpf_instance.perf_buffer_poll(timeout=self.poll_timeout_ms)

            # Drain residual events on stop
            for _ in range(5):
                self.bpf_instance.perf_buffer_poll(timeout=20)
        except Exception as e:
            logger.error(f"Collector polling loop error: {e}")
            if self.writer:
                self.writer.write_event(
                    DiagnosticEvent(
                        event_type=EventType.COLLECTOR_DIAGNOSTIC.value,
                        timestamp_ns=time.monotonic_ns(),
                        subsystem="collector_loop",
                        status="ERROR",
                        message=f"Polling loop terminated with error: {str(e)}",
                    )
                )

    def start(self):
        """Starts tracing and writing events to the output path."""
        self.writer = EventWriter(self.output_path)
        self.initialize_bpf()

        # Emit collector start diagnostic
        self.writer.write_event(
            DiagnosticEvent(
                event_type=EventType.COLLECTOR_DIAGNOSTIC.value,
                timestamp_ns=time.monotonic_ns(),
                subsystem="collector",
                status="INFO",
                message="eBPF collector initialized and tracing started",
                details={
                    "target_pids": self.target_pids,
                    "perf_page_cnt": self.perf_page_cnt,
                },
            )
        )
        self.writer.flush()

        self._stop_requested.clear()
        self._thread = threading.Thread(target=self._polling_loop, daemon=True, name="BPFCollectorThread")
        self._thread.start()
        self.is_active = True
        logger.info(f"Collector active. Output directed to {self.output_path}")

    def stop(self):
        """Stops tracing, drains remaining events, and flushes output."""
        if not self.is_active:
            return

        logger.info("Stopping eBPF collector and flushing buffers...")
        self._stop_requested.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3.0)

        # Write dropped event stats
        loss_rate = 0.0
        tot = self.total_events_emitted + self.total_events_lost
        if tot > 0:
            loss_rate = self.total_events_lost / tot

        if self.writer:
            self.writer.write_event(
                DroppedEventStats(
                    event_type=EventType.DROPPED_EVENT_STATS.value,
                    timestamp_ns=time.monotonic_ns(),
                    total_events_emitted=self.total_events_emitted,
                    total_events_lost=self.total_events_lost,
                    loss_rate=loss_rate,
                )
            )
            self.writer.write_event(
                DiagnosticEvent(
                    event_type=EventType.COLLECTOR_DIAGNOSTIC.value,
                    timestamp_ns=time.monotonic_ns(),
                    subsystem="collector",
                    status="INFO",
                    message="eBPF collector shutdown complete",
                    details={
                        "total_emitted": self.total_events_emitted,
                        "total_lost": self.total_events_lost,
                    },
                )
            )
            self.writer.close()
            self.writer = None

        if self.bpf_instance:
            self.bpf_instance.cleanup()
            self.bpf_instance = None

        self.is_active = False
        logger.info("eBPF collector stopped successfully.")

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()
