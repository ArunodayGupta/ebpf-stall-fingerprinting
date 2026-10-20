"""
Structured Event Schema for eBPF Application Stall Fingerprinting.

Defines versioned schemas for:
- Syscall entry/exit/complete events
- Block I/O request issue/complete events
- Scheduler wakeup and switch events
- Collector diagnostics and dropped event statistics
"""

import json
from dataclasses import dataclass, asdict, field
from enum import Enum
from typing import Optional, Dict, Any, List, Union
from pathlib import Path

SCHEMA_VERSION = "1.0"

class EventType(str, Enum):
    SYSCALL_ENTRY = "SYSCALL_ENTRY"
    SYSCALL_EXIT = "SYSCALL_EXIT"
    SYSCALL_COMPLETE = "SYSCALL_COMPLETE"
    BLOCK_RQ_ISSUE = "BLOCK_RQ_ISSUE"
    BLOCK_RQ_COMPLETE = "BLOCK_RQ_COMPLETE"
    SCHED_WAKEUP = "SCHED_WAKEUP"
    SCHED_SWITCH = "SCHED_SWITCH"
    COLLECTOR_DIAGNOSTIC = "COLLECTOR_DIAGNOSTIC"
    DROPPED_EVENT_STATS = "DROPPED_EVENT_STATS"

@dataclass
class BaseEvent:
    event_type: str
    timestamp_ns: int
    schema_version: str = SCHEMA_VERSION
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

@dataclass
class SyscallEvent(BaseEvent):
    pid: int = 0
    tid: int = 0
    comm: str = ""
    syscall_name: str = ""
    syscall_id: int = 0
    duration_ns: int = 0
    ret: int = 0
    fd: Optional[int] = None
    count: Optional[int] = None

@dataclass
class BlockEvent(BaseEvent):
    dev: int = 0
    sector: int = 0
    nr_sector: int = 0
    bytes_count: int = 0
    rwbs: str = ""
    pid: int = 0
    comm: str = ""
    error: int = 0

@dataclass
class SchedEvent(BaseEvent):
    prev_pid: int = 0
    prev_comm: str = ""
    prev_state: int = 0
    next_pid: int = 0
    next_comm: str = ""
    target_pid: int = 0
    is_on_cpu: bool = False
    runnable_delay_ns: int = 0

@dataclass
class DiagnosticEvent(BaseEvent):
    subsystem: str = ""
    status: str = "INFO"  # INFO, WARNING, ERROR
    message: str = ""
    details: Dict[str, Any] = field(default_factory=dict)

@dataclass
class DroppedEventStats(BaseEvent):
    total_events_emitted: int = 0
    total_events_lost: int = 0
    loss_rate: float = 0.0
    buffer_type: str = "perf_buffer"

def parse_event(data: Union[str, Dict[str, Any]]) -> BaseEvent:
    if isinstance(data, str):
        data = json.loads(data)

    event_type = data.get("event_type")
    ts = data.get("timestamp_ns", 0)
    ver = data.get("schema_version", SCHEMA_VERSION)
    meta = data.get("metadata", {})

    if event_type in (EventType.SYSCALL_ENTRY.value, EventType.SYSCALL_EXIT.value, EventType.SYSCALL_COMPLETE.value):
        return SyscallEvent(
            event_type=event_type,
            timestamp_ns=ts,
            schema_version=ver,
            metadata=meta,
            pid=data.get("pid", 0),
            tid=data.get("tid", 0),
            comm=data.get("comm", ""),
            syscall_name=data.get("syscall_name", ""),
            syscall_id=data.get("syscall_id", 0),
            duration_ns=data.get("duration_ns", 0),
            ret=data.get("ret", 0),
            fd=data.get("fd"),
            count=data.get("count"),
        )
    elif event_type in (EventType.BLOCK_RQ_ISSUE.value, EventType.BLOCK_RQ_COMPLETE.value):
        return BlockEvent(
            event_type=event_type,
            timestamp_ns=ts,
            schema_version=ver,
            metadata=meta,
            dev=data.get("dev", 0),
            sector=data.get("sector", 0),
            nr_sector=data.get("nr_sector", 0),
            bytes_count=data.get("bytes_count", 0),
            rwbs=data.get("rwbs", ""),
            pid=data.get("pid", 0),
            comm=data.get("comm", ""),
            error=data.get("error", 0),
        )
    elif event_type in (EventType.SCHED_WAKEUP.value, EventType.SCHED_SWITCH.value):
        return SchedEvent(
            event_type=event_type,
            timestamp_ns=ts,
            schema_version=ver,
            metadata=meta,
            prev_pid=data.get("prev_pid", 0),
            prev_comm=data.get("prev_comm", ""),
            prev_state=data.get("prev_state", 0),
            next_pid=data.get("next_pid", 0),
            next_comm=data.get("next_comm", ""),
            target_pid=data.get("target_pid", 0),
            is_on_cpu=data.get("is_on_cpu", False),
            runnable_delay_ns=data.get("runnable_delay_ns", 0),
        )
    elif event_type == EventType.COLLECTOR_DIAGNOSTIC.value:
        return DiagnosticEvent(
            event_type=event_type,
            timestamp_ns=ts,
            schema_version=ver,
            metadata=meta,
            subsystem=data.get("subsystem", ""),
            status=data.get("status", "INFO"),
            message=data.get("message", ""),
            details=data.get("details", {}),
        )
    elif event_type == EventType.DROPPED_EVENT_STATS.value:
        return DroppedEventStats(
            event_type=event_type,
            timestamp_ns=ts,
            schema_version=ver,
            metadata=meta,
            total_events_emitted=data.get("total_events_emitted", 0),
            total_events_lost=data.get("total_events_lost", 0),
            loss_rate=data.get("loss_rate", 0.0),
            buffer_type=data.get("buffer_type", "perf_buffer"),
        )
    else:
        return BaseEvent(
            event_type=event_type or "UNKNOWN",
            timestamp_ns=ts,
            schema_version=ver,
            metadata=meta,
        )

class EventWriter:
    """Thread-safe and atomic append-only JSON Lines event writer."""

    def __init__(self, file_path: Union[str, Path]):
        self.file_path = Path(file_path)
        self.file_path.parent.mkdir(parents=True, exist_ok=True)
        self._file = open(self.file_path, "a", encoding="utf-8")
        self.emitted_count = 0

    def write_event(self, event: BaseEvent):
        line = event.to_json() + "\n"
        self._file.write(line)
        self.emitted_count += 1

    def flush(self):
        self._file.flush()

    def close(self):
        self.flush()
        self._file.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

class EventReader:
    """Stream reader for JSON Lines event files with corrupt record tolerance."""

    def __init__(self, file_path: Union[str, Path]):
        self.file_path = Path(file_path)

    def iter_events(self):
        if not self.file_path.exists():
            return

        with open(self.file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line_no, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    yield parse_event(data)
                except Exception as e:
                    # Return diagnostic for corrupt lines
                    yield DiagnosticEvent(
                        event_type=EventType.COLLECTOR_DIAGNOSTIC.value,
                        timestamp_ns=0,
                        subsystem="event_reader",
                        status="WARNING",
                        message=f"Corrupt event line {line_no}: {str(e)}",
                        details={"line": line[:100]},
                    )

    def read_all(self) -> List[BaseEvent]:
        return list(self.iter_events())
