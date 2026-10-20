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
from typing import List, Dict, Any, Optional
from concurrent.futures import ProcessPoolExecutor, as_completed
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

class WorkloadSupervisor:
    """
    Coordinates multi-concurrency workload executions.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}

    def execute_workload_trial(
        self,
        workload_type: str,
        trial_id: str,
        concurrency: int = 1,
        params: Optional[Dict[str, Any]] = None,
    ) -> List[WorkloadOperationRecord]:
        p = params or {}
        records: List[WorkloadOperationRecord] = []

        if concurrency == 1:
            rec = _dispatch_single_workload(workload_type, trial_id, concurrency, p)
            records.append(rec)
        else:
            with ProcessPoolExecutor(max_workers=concurrency) as executor:
                futures = [
                    executor.submit(_dispatch_single_workload, workload_type, f"{trial_id}_worker_{i}", concurrency, p)
                    for i in range(concurrency)
                ]
                for fut in as_completed(futures):
                    try:
                        records.append(fut.result())
                    except Exception as e:
                        logger.error(f"Concurrent worker execution failed: {e}")
                        raise

        return records
