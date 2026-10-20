"""
Unit tests for event correlation and non-overlapping interval union calculations.
"""

import pytest
from stall_fingerprint.correlation import compute_interval_union, EventCorrelator
from stall_fingerprint.event_schema import SyscallEvent, EventType, BlockEvent, SchedEvent
from workloads.workload_utils import WorkloadOperationRecord

def test_interval_union_non_overlapping():
    intervals = [(10, 20), (30, 40), (50, 60)]
    union_len = compute_interval_union(intervals, clip_min=0, clip_max=100)
    assert union_len == 30

def test_interval_union_overlapping_and_nested():
    # (10, 30) and (20, 40) overlap -> (10, 40) length 30
    # (25, 35) is nested inside -> no extra length
    # (50, 60) is separate -> length 10
    intervals = [(10, 30), (20, 40), (25, 35), (50, 60)]
    union_len = compute_interval_union(intervals, clip_min=0, clip_max=100)
    assert union_len == 40  # 30 + 10

def test_interval_union_clipping():
    intervals = [(0, 50), (60, 100)]
    # Clip window to [20, 80]:
    # (0, 50) clipped to (20, 50) length 30
    # (60, 100) clipped to (60, 80) length 20
    union_len = compute_interval_union(intervals, clip_min=20, clip_max=80)
    assert union_len == 50

def test_interval_union_empty():
    assert compute_interval_union([], 0, 100) == 0
    assert compute_interval_union([(10, 20)], 50, 100) == 0

def test_event_correlator_matching():
    op = WorkloadOperationRecord(
        trial_id="test_op",
        workload_type="test",
        operation_id=1,
        pid=5000,
        tid=5000,
        start_ns=1000,
        end_ns=2000,
        duration_ns=1000,
        intervention_label="test",
        expected_label="test",
    )

    events = [
        # In-window, matching PID
        SyscallEvent(event_type=EventType.SYSCALL_COMPLETE.value, timestamp_ns=1500, pid=5000, duration_ns=200),
        # In-window, different PID
        SyscallEvent(event_type=EventType.SYSCALL_COMPLETE.value, timestamp_ns=1600, pid=9999, duration_ns=100),
        # Out-of-window
        SyscallEvent(event_type=EventType.SYSCALL_COMPLETE.value, timestamp_ns=3000, pid=5000, duration_ns=100),
        # In-window block event
        BlockEvent(event_type=EventType.BLOCK_RQ_COMPLETE.value, timestamp_ns=1700, bytes_count=4096),
    ]

    correlator = EventCorrelator(window_margin_ns=0)
    cw = correlator.correlate_operation(op, events)

    assert len(cw.syscall_events) == 1
    assert cw.syscall_events[0].pid == 5000
    assert len(cw.block_events) == 1
    assert cw.block_events[0].bytes_count == 4096
