"""
Workload B: Sequential File Reads (Target for io_wait_dominated).

Generates a test file in an isolated temporary directory and reads it sequentially
using controlled buffer sizes. Supports optional posix_fadvise cache-eviction advice.
"""

import os
import sys
from pathlib import Path
from workloads.workload_utils import (
    get_monotonic_ns,
    isolate_test_directory,
    cleanup_file,
    apply_cold_cache_advice,
    WorkloadOperationRecord,
)

def run_read_workload(
    trial_id: str,
    file_size_mb: int = 16,
    chunk_size_kb: int = 64,
    cold_cache: bool = True,
    concurrency: int = 1,
) -> WorkloadOperationRecord:
    pid = os.getpid()
    tid = pid

    test_dir = isolate_test_directory()
    test_file = test_dir / f"read_test_{trial_id}_{pid}.dat"

    # 1. Prepare test file with pseudo-random bytes
    chunk_bytes = chunk_size_kb * 1024
    total_bytes = file_size_mb * 1024 * 1024
    chunks_count = total_bytes // chunk_bytes

    dummy_payload = os.urandom(chunk_bytes)
    with open(test_file, "wb") as f:
        for _ in range(chunks_count):
            f.write(dummy_payload)
        f.flush()
        os.fsync(f.fileno())

    # 2. Apply best-effort cold cache advice
    fd = os.open(str(test_file), os.O_RDONLY)
    advised_cold = False
    if cold_cache:
        advised_cold = apply_cold_cache_advice(fd)

    # 3. Timed sequential read operations
    t_start = get_monotonic_ns()
    total_read = 0
    while True:
        buf = os.read(fd, chunk_bytes)
        if not buf:
            break
        total_read += len(buf)

    t_end = get_monotonic_ns()
    os.close(fd)
    duration = t_end - t_start

    # Clean up test file
    cleanup_file(test_file)

    return WorkloadOperationRecord(
        trial_id=trial_id,
        workload_type="file_read_sequential",
        operation_id=1,
        pid=pid,
        tid=tid,
        start_ns=t_start,
        end_ns=t_end,
        duration_ns=duration,
        intervention_label="file_read_sequential",
        expected_label="io_wait_dominated",
        concurrency=concurrency,
        parameters={
            "file_size_mb": file_size_mb,
            "chunk_size_kb": chunk_size_kb,
            "cold_cache_advised": advised_cold,
            "total_bytes_read": total_read,
        },
    )

if __name__ == "__main__":
    rec = run_read_workload("standalone_test", file_size_mb=4)
    print(rec.to_json())
