"""
Workload A: CPU-Bound Computation (Control for cpu_syscall_dominated).

Performs deterministic, bounded CPU calculations (iterated SHA-256 / arithmetic)
with strictly no file I/O inside the timed execution window.
"""

import os
import sys
import hashlib
from typing import Dict, Any, List
from workloads.workload_utils import (
    get_monotonic_ns,
    WorkloadOperationRecord,
)

def run_cpu_workload(
    trial_id: str,
    iterations: int = 1000000,
    concurrency: int = 1,
) -> WorkloadOperationRecord:
    pid = os.getpid()
    tid = pid

    t_start = get_monotonic_ns()

    # Deterministic CPU loop
    state = b"ebpf_stall_benchmark_seed_data"
    for i in range(iterations):
        state = hashlib.sha256(state + (i % 256).to_bytes(1, "little")).digest()

    t_end = get_monotonic_ns()
    duration = t_end - t_start

    return WorkloadOperationRecord(
        trial_id=trial_id,
        workload_type="cpu_bound",
        operation_id=1,
        pid=pid,
        tid=tid,
        start_ns=t_start,
        end_ns=t_end,
        duration_ns=duration,
        intervention_label="cpu_bound",
        expected_label="cpu_syscall_dominated",
        concurrency=concurrency,
        parameters={"iterations": iterations, "digest_prefix": state[:4].hex()},
    )

if __name__ == "__main__":
    rec = run_cpu_workload("standalone_test", iterations=200000)
    print(rec.to_json())
