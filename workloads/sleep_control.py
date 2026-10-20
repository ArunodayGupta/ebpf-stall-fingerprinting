"""
Negative-Control Workload: Intentional Sleep (Control for indeterminate).

Performs an explicit sleep delay. This validates that intentional, voluntary sleeps
(where the task is blocked off-CPU in TASK_INTERRUPTIBLE, NOT runnable)
are not misclassified as scheduler-wait-dominated or I/O-wait-dominated.
The ground truth expected class is indeterminate.
"""

import os
import sys
import time
from workloads.workload_utils import (
    get_monotonic_ns,
    WorkloadOperationRecord,
)

def run_sleep_workload(
    trial_id: str,
    sleep_duration_ms: int = 150,
    concurrency: int = 1,
) -> WorkloadOperationRecord:
    pid = os.getpid()
    tid = pid

    t_start = get_monotonic_ns()
    time.sleep(sleep_duration_ms / 1000.0)
    t_end = get_monotonic_ns()
    duration = t_end - t_start

    return WorkloadOperationRecord(
        trial_id=trial_id,
        workload_type="intentional_sleep_control",
        operation_id=1,
        pid=pid,
        tid=tid,
        start_ns=t_start,
        end_ns=t_end,
        duration_ns=duration,
        intervention_label="intentional_sleep",
        expected_label="indeterminate",
        concurrency=concurrency,
        parameters={"sleep_duration_ms": sleep_duration_ms},
    )

if __name__ == "__main__":
    rec = run_sleep_workload("standalone_test", sleep_duration_ms=50)
    print(rec.to_json())
