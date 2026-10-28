"""
Workload Supervisor and Execution Coordinator.

Manages execution of controlled workloads:
- Spawns unprivileged workload processes
- Manages concurrency across worker threads/processes
- Collects workload operation records and ground truth labels
- Measures unmonitored baseline runs vs monitored tracing runs
"""

import os
import sys
import time
import logging
import multiprocessing as mp
from typing import List, Dict, Any, Optional, Callable
from workloads.workload_utils import WorkloadOperationRecord
from workloads.cpu_workload import run_cpu_workload
from workloads.read_workload import run_read_workload
from workloads.write_workload import run_write_workload
from workloads.scheduler_contention import run_scheduler_contention_workload
from workloads.sleep_control import run_sleep_workload

logger = logging.getLogger("stall_fingerprint.supervisor")

def _dispatch_single_workload(
    workload_type: str,
    trial_id: str,
    concurrency: int,
    params: Dict[str, Any],
) -> WorkloadOperationRecord:
    """Dispatches execution to the appropriate workload function."""
    if workload_type == "cpu_bound":
        iters = params.get("cpu_iterations", 1000000)
        return run_cpu_workload(trial_id=trial_id, iterations=iters, concurrency=concurrency)
    elif workload_type == "file_read_sequential":
        fsize = params.get("file_size_mb", 16)
        csize = params.get("chunk_size_kb", 64)
        cold = params.get("cold_cache", True)
        return run_read_workload(trial_id=trial_id, file_size_mb=fsize, chunk_size_kb=csize, cold_cache=cold, concurrency=concurrency)
    elif workload_type == "file_write_sync":
        fsize = params.get("file_size_mb", 16)
        csize = params.get("chunk_size_kb", 64)
        sync_mode = params.get("sync_mode", "fsync")
        return run_write_workload(trial_id=trial_id, file_size_mb=fsize, chunk_size_kb=csize, sync_mode=sync_mode, concurrency=concurrency)
    elif workload_type == "scheduler_contention":
        iters = params.get("cpu_iterations", 500000)
        workers = params.get("contention_worker_count", 4)
        return run_scheduler_contention_workload(trial_id=trial_id, target_iterations=iters, competing_workers=workers, concurrency=concurrency)
    elif workload_type == "intentional_sleep_control":
        s_dur = params.get("sleep_duration_ms", 150)
        return run_sleep_workload(trial_id=trial_id, sleep_duration_ms=s_dur, concurrency=concurrency)
    else:
        raise ValueError(f"Unknown workload type: {workload_type}")

def _worker_process_entry(
    workload_type: str,
    worker_trial_id: str,
    parent_trial_id: str,
    concurrency: int,
    params: Dict[str, Any],
    ready_queue: Any,
    start_event: Any,
    result_queue: Any,
):
    """Worker entry point enforcing registration before beginning timed execution."""
    try:
        pid = os.getpid()
        ready_queue.put(pid)
        # Block until supervisor has registered PID in kernel BPF map
        start_event.wait()
        rec = _dispatch_single_workload(workload_type, worker_trial_id, concurrency, params)
        rec.parent_trial_id = parent_trial_id
        result_queue.put((True, rec))
    except Exception as e:
        result_queue.put((False, str(e)))

class WorkloadSupervisor:
    """
    Coordinates multi-concurrency workload executions with pre-execution PID registration.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}

    def execute_workload_trial(
        self,
        workload_type: str,
        trial_id: str,
        concurrency: int = 1,
        params: Optional[Dict[str, Any]] = None,
        register_pid_fn: Optional[Callable[[int], None]] = None,
    ) -> List[WorkloadOperationRecord]:
        p_params = params or {}
        records: List[WorkloadOperationRecord] = []

        if concurrency == 1:
            if register_pid_fn:
                register_pid_fn(os.getpid())
            rec = _dispatch_single_workload(workload_type, trial_id, concurrency, p_params)
            rec.parent_trial_id = trial_id
            records.append(rec)
        else:
            ready_queue = mp.Queue()
            start_event = mp.Event()
            result_queue = mp.Queue()
            procs = []

            for i in range(concurrency):
                worker_trial_id = f"{trial_id}_worker_{i}"
                p = mp.Process(
                    target=_worker_process_entry,
                    args=(
                        workload_type,
                        worker_trial_id,
                        trial_id,
                        concurrency,
                        p_params,
                        ready_queue,
                        start_event,
                        result_queue,
                    ),
                    daemon=False,
                )
                p.start()
                procs.append(p)

            # Wait for all workers to spawn and report their PIDs
            worker_pids = []
            for _ in range(concurrency):
                w_pid = ready_queue.get(timeout=15.0)
                worker_pids.append(w_pid)
                if register_pid_fn:
                    register_pid_fn(w_pid)

            # Release startup barrier: all processes start timed work simultaneously
            start_event.set()

            for _ in range(concurrency):
                success, val = result_queue.get(timeout=120.0)
                if success:
                    records.append(val)
                else:
                    raise RuntimeError(f"Concurrent worker execution failed: {val}")

            for p in procs:
                p.join(timeout=5.0)

        return records
