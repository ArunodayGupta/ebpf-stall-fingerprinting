"""
Unit tests for quantitative feature extraction.
"""

import pytest
from stall_fingerprint.correlation import WindowCorrelatedEvents
from stall_fingerprint.feature_extraction import extract_features_from_correlated_window
from stall_fingerprint.event_schema import SyscallEvent, BlockEvent, SchedEvent, EventType
from workloads.workload_utils import WorkloadOperationRecord

def test_feature_extraction_proportions():
    op = WorkloadOperationRecord(
        trial_id="t1",
        workload_type="file_read_sequential",
        operation_id=1,
        pid=1000,
        tid=1000,
        start_ns=10_000_000,
        end_ns=20_000_000,
        duration_ns=10_000_000,  # 10 ms
        intervention_label="file_read",
        expected_label="io_wait_dominated",
    )

    # 4 ms syscall at 14 ms
    sys_ev = SyscallEvent(
        event_type=EventType.SYSCALL_COMPLETE.value,
        timestamp_ns=14_000_000,
        pid=1000,
        syscall_name="read",
        duration_ns=4_000_000,
    )
    # Block completion
    blk_ev = BlockEvent(
        event_type=EventType.BLOCK_RQ_COMPLETE.value,
        timestamp_ns=13_500_000,
        bytes_count=65536,
    )
    # 2 ms runnable wait
    sched_ev = SchedEvent(
        event_type=EventType.SCHED_SWITCH.value,
        timestamp_ns=17_000_000,
        target_pid=1000,
        is_on_cpu=True,
        runnable_delay_ns=2_000_000,
    )

    cw = WindowCorrelatedEvents(
        operation=op,
        syscall_events=[sys_ev],
        block_events=[blk_ev],
        sched_events=[sched_ev],
    )

    feat = extract_features_from_correlated_window(cw)

    assert feat["wall_duration_ms"] == 10.0
    assert feat["syscall_count"] == 1
    assert feat["read_count"] == 1
    assert feat["non_overlap_syscall_ns"] == 4_000_000
    assert feat["syscall_duration_ratio"] == 0.40
    assert feat["has_block_activity"] == 1
    assert feat["block_total_bytes"] == 65536
    assert feat["runnable_wait_ns"] == 2_000_000
    assert feat["sched_wait_ratio"] == 0.20
    # On-CPU is 10ms - (4ms + 2ms) = 4ms -> 0.40
    assert feat["on_cpu_ratio"] == 0.40
    assert 0.0 <= feat["syscall_duration_ratio"] <= 1.0
    assert 0.0 <= feat["sched_wait_ratio"] <= 1.0
    assert 0.0 <= feat["on_cpu_ratio"] <= 1.0

def test_feature_extraction_empty_window():
    op = WorkloadOperationRecord(
        trial_id="t_empty",
        workload_type="intentional_sleep_control",
        operation_id=1,
        pid=1000,
        tid=1000,
        start_ns=0,
        end_ns=50_000_000,
        duration_ns=50_000_000,
        intervention_label="sleep",
        expected_label="indeterminate",
    )
    cw = WindowCorrelatedEvents(operation=op)
    feat = extract_features_from_correlated_window(cw)

    assert feat["is_empty_window"] == 1
    assert feat["unobserved_ratio"] == 1.0
    assert feat["on_cpu_ratio"] == 0.0
