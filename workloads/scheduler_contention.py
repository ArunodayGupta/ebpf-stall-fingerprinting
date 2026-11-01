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
import math
from typing import Dict, Any, List, Optional
from workloads.workload_utils import (
    get_monotonic_ns,
    set_thread_comm,
    WorkloadOperationRecord,
)

def effective_competing_worker_count(
    configured_workers: int,
    concurrency: int,
    available_cpus: int,
    cpu_oversubscription: int = 2,
    pinned_to_single_cpu: bool = False,
) -> int:
    """Scale background workers for a repeatable, CPU-saturated intervention."""
    concurrency = max(concurrency, 1)
    available_cpus = max(available_cpus, 1)
    cpu_oversubscription = max(cpu_oversubscription, 1)
    if pinned_to_single_cpu:
        return max(configured_workers, cpu_oversubscription)
    return max(
        configured_workers,
        math.ceil(available_cpus * cpu_oversubscription / concurrency),
    )

def _contention_worker(stop_event: mp.Event, target_cpu: Optional[int] = None):
    """Stress worker spinning on CPU until signaled to stop."""
    # Do not inherit the target worker's telemetry marker across fork.
    set_thread_comm("sfp-bg")
    if target_cpu is not None:
        try:
            os.sched_setaffinity(0, {target_cpu})
        except (AttributeError, OSError):
            pass
    x = 0
    while not stop_event.is_set():
        x = (x + 1) * 3 % 10000007

def run_scheduler_contention_workload(
    trial_id: str,
    target_iterations: int = 500000,
    competing_workers: int = 4,
    concurrency: int = 1,
    cpu_oversubscription: int = 2,
) -> WorkloadOperationRecord:
    pid = os.getpid()
    tid = pid

    # Pin the controlled target and its stress workers to one allowed CPU. This
    # creates deliberate runqueue contention even when WSL exposes many CPUs.
    original_affinity = None
    target_cpu = None
    try:
        original_affinity = set(os.sched_getaffinity(0))
        available_cpus = len(original_affinity)
        target_cpu = min(original_affinity)
        os.sched_setaffinity(0, {target_cpu})
    except (AttributeError, OSError):
        available_cpus = os.cpu_count() or 1
        original_affinity = None
        target_cpu = None
    effective_competing_workers = effective_competing_worker_count(
        configured_workers=competing_workers,
        concurrency=concurrency,
        available_cpus=available_cpus,
        cpu_oversubscription=cpu_oversubscription,
        pinned_to_single_cpu=target_cpu is not None,
    )

    stop_event = mp.Event()
    worker_procs = []
    try:
        for _ in range(effective_competing_workers):
            p = mp.Process(target=_contention_worker, args=(stop_event, target_cpu), daemon=True)
            p.start()
            worker_procs.append(p)

        # Allow workers to load the selected CPU's runqueue.
        time.sleep(0.05)

        t_start = get_monotonic_ns()
        # Target computation
        state = b"scheduler_contention_target_payload"
        for i in range(target_iterations):
            state = hashlib.sha256(state + (i % 256).to_bytes(1, "little")).digest()

        t_end = get_monotonic_ns()
        duration = t_end - t_start
    finally:
        # Terminate background contention workers cleanly.
        stop_event.set()
        for p in worker_procs:
            p.join(timeout=1.0)
            if p.is_alive():
                p.terminate()
                p.join(timeout=1.0)
        if original_affinity is not None:
            os.sched_setaffinity(0, original_affinity)

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
            "configured_competing_workers_per_target": competing_workers,
            "competing_workers": effective_competing_workers,
            "trial_competing_workers": effective_competing_workers * concurrency,
            "logical_cpus": available_cpus,
            "cpu_oversubscription": max(cpu_oversubscription, 1),
            "target_cpu": target_cpu,
            "affinity_pinned": target_cpu is not None,
        },
    )

if __name__ == "__main__":
    rec = run_scheduler_contention_workload("standalone_test", target_iterations=100000, competing_workers=2)
    print(rec.to_json())
