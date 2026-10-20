"""
Workload C: File Writes with Synchronization (Target for io_wait_dominated).

Performs bounded writes to a dedicated temporary file and executes an explicit
fsync / fdatasync synchronization, measuring write time and sync time separately.
"""

import os
import sys
from pathlib import Path
from workloads.workload_utils import (
    get_monotonic_ns,
    isolate_test_directory,
    cleanup_file,
    WorkloadOperationRecord,
)

def run_write_workload(
    trial_id: str,
    file_size_mb: int = 16,
    chunk_size_kb: int = 64,
    sync_mode: str = "fsync",
    concurrency: int = 1,
) -> WorkloadOperationRecord:
    pid = os.getpid()
    tid = pid

    test_dir = isolate_test_directory()
    test_file = test_dir / f"write_test_{trial_id}_{pid}.dat"

    chunk_bytes = chunk_size_kb * 1024
    total_bytes = file_size_mb * 1024 * 1024
    chunks_count = total_bytes // chunk_bytes
    dummy_payload = os.urandom(chunk_bytes)

    fd = os.open(str(test_file), os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o644)

    t_start = get_monotonic_ns()
    # Write loop
    bytes_written = 0
    for _ in range(chunks_count):
        written = os.write(fd, dummy_payload)
        bytes_written += written

    t_write_done = get_monotonic_ns()

    # Sync phase
    if sync_mode == "fdatasync" and hasattr(os, "fdatasync"):
        os.fdatasync(fd)
    else:
        os.fsync(fd)

    t_end = get_monotonic_ns()
    os.close(fd)
    duration = t_end - t_start

    # Clean up test file
    cleanup_file(test_file)

    return WorkloadOperationRecord(
        trial_id=trial_id,
        workload_type="file_write_sync",
        operation_id=1,
        pid=pid,
        tid=tid,
        start_ns=t_start,
        end_ns=t_end,
        duration_ns=duration,
        intervention_label="file_write_sync",
        expected_label="io_wait_dominated",
        concurrency=concurrency,
        parameters={
            "file_size_mb": file_size_mb,
            "chunk_size_kb": chunk_size_kb,
            "sync_mode": sync_mode,
            "bytes_written": bytes_written,
            "write_duration_ns": t_write_done - t_start,
            "sync_duration_ns": t_end - t_write_done,
        },
    )

if __name__ == "__main__":
    rec = run_write_workload("standalone_test", file_size_mb=4)
    print(rec.to_json())
