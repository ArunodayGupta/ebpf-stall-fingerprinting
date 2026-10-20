"""
Workload D: Scheduler Contention (Target for scheduler_wait_dominated).

Spawns competing CPU stress worker processes to saturate CPU runqueues
while the target task performs a bounded computation, inducing runnable wait delays.
"""

import os
import sys
import time
import hashlib
import multiprocessing as mp
from typing import Dict, Any, List
from workloads.workload_utils import (
    get_monotonic_ns,
    WorkloadOperationRecord,
)

def _contention_worker(stop_event: mp.Event):
    """Stress worker spinning on CPU until signaled to stop."""
    x = 0
    while not stop_event.is_set():
        x = (x + 1) * 3 % 10000007

def run_scheduler_contention_workload(
    trial_id: str,
    target_iterations: int = 500000,
    competing_workers: int = 4,
    concurrency: int = 1,
) -> WorkloadOperationRecord:
    pid = os.getpid()
    tid = pid

    stop_event = mp.Event()
    worker_procs = []
    for _ in range(competing_workers):
        p = mp.Process(target=_contention_worker, args=(stop_event,), daemon=True)
        p.start()
        worker_procs.append(p)

    # Allow workers to spin up and load scheduler runqueues
    time.sleep(0.05)

    t_start = get_monotonic_ns()
    # Target computation
    state = b"scheduler_contention_target_payload"
    for i in range(target_iterations):
        state = hashlib.sha256(state + (i % 256).to_bytes(1, "little")).digest()

    t_end = get_monotonic_ns()
    duration = t_end - t_start

    # Terminate background contention workers cleanly
    stop_event.set()
    for p in worker_procs:
        p.join(timeout=1.0)
        if p.is_alive():
            p.terminate()

    return WorkloadOperationRecord(
        trial_id=trial_id,
        workload_type="scheduler_contention",
        operation_id=1,
        pid=pid,
        tid=tid,
        start_ns=t_start,
        end_ns=t_end,
        duration_ns=duration,
        intervention_label="scheduler_contention",
        expected_label="scheduler_wait_dominated",
        concurrency=concurrency,
        parameters={
            "target_iterations": target_iterations,
            "competing_workers": competing_workers,
            "logical_cpus": os.cpu_count() or 1,
        },
    )

if __name__ == "__main__":
    rec = run_scheduler_contention_workload("standalone_test", target_iterations=100000, competing_workers=2)
    print(rec.to_json())
