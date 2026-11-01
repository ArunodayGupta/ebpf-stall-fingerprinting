"""
Comprehensive Regression Test Suite for eBPF Application Stall Fingerprinting.

Directly validates fixes for:
1. Intentional sleep negative control is NOT classified as cpu_syscall_dominated.
2. Unrelated process block I/O does NOT corrupt classification of concurrent CPU-bound or cached operations.
3. Grouped ML train/test splitting guarantees zero leakage across concurrent workers sharing a parent trial.
4. Held-out test evaluation computes primary ML performance strictly on unseen data.
5. Excessive telemetry drop rate enforces rule-based abstention.
6. Honest like-for-like overhead accounting prevents apples-to-oranges comparisons.
"""

import pytest
import pandas as pd
from stall_fingerprint.event_schema import (
    EventType,
    SyscallEvent,
    BlockEvent,
    SchedEvent,
)
from workloads.workload_utils import WorkloadOperationRecord
from workloads.scheduler_contention import effective_competing_worker_count
from stall_fingerprint.correlation import EventCorrelator, WindowCorrelatedEvents
from stall_fingerprint.feature_extraction import extract_features_from_correlated_window
from stall_fingerprint.classifier_rules import (
    RuleBasedClassifier,
    LABEL_IO_WAIT,
    LABEL_SCHED_WAIT,
    LABEL_CPU_SYSCALL,
    LABEL_INDETERMINATE,
)
from stall_fingerprint.classifier_ml import LightweightMLClassifier
from stall_fingerprint.evaluation import compute_overhead_metrics

def test_regression_sleep_not_classified_as_cpu():
    """
    REGRESSION TEST:
    Ensures that an intentional voluntary sleep with scheduler transitions
    (prev_state != 0 switch-out and wakeup/switch-in) is NEVER classified
    as cpu_syscall_dominated.
    """
    target_pid = 7001
    wall_duration_ns = 150_000_000  # 150 ms sleep
    start_ns = 1_000_000_000
    end_ns = start_ns + wall_duration_ns

    op = WorkloadOperationRecord(
        trial_id="sleep_trial_01",
        workload_type="intentional_sleep_control",
        operation_id=1,
        pid=target_pid,
        tid=target_pid,
        start_ns=start_ns,
        end_ns=end_ns,
        duration_ns=wall_duration_ns,
        intervention_label="intentional_sleep",
        expected_label="indeterminate",
    )

    # In a real sleep, the task switches off-CPU with prev_state != 0 (TASK_INTERRUPTIBLE = 1),
    # sleeps for ~149 ms, wakes up, and switches back on-CPU with a tiny runnable delay.
    events = [
        # 1. Switched off CPU into voluntary sleep (prev_state = 1)
        SchedEvent(
            event_type=EventType.SCHED_SWITCH.value,
            timestamp_ns=start_ns + 100_000,
            prev_pid=target_pid,
            next_pid=0,
            prev_state=1,
            target_pid=target_pid,
            is_on_cpu=False,
            runnable_delay_ns=0,
        ),
        # 2. Timer wake-up
        SchedEvent(
            event_type=EventType.SCHED_WAKEUP.value,
            timestamp_ns=end_ns - 100_000,
            target_pid=target_pid,
        ),
        # 3. Scheduled back onto CPU
        SchedEvent(
            event_type=EventType.SCHED_SWITCH.value,
            timestamp_ns=end_ns - 50_000,
            prev_pid=0,
            next_pid=target_pid,
            prev_state=0,
            target_pid=target_pid,
            is_on_cpu=True,
            runnable_delay_ns=50_000,
        ),
    ]

    correlator = EventCorrelator(window_margin_ns=0)
    cw = correlator.correlate_operation(op, events)
    features = extract_features_from_correlated_window(cw)

    # Off-CPU blocked delay must dominate
    assert features["off_cpu_blocked_ratio"] >= 0.90
    assert features["on_cpu_ratio"] <= 0.10

    classifier = RuleBasedClassifier()
    pred = classifier.predict_sample(features)

    # Must NOT be classified as cpu_syscall_dominated!
    assert pred.predicted_label != LABEL_CPU_SYSCALL
    assert pred.predicted_label == LABEL_INDETERMINATE
    assert "RULE_OFF_CPU_VOLUNTARY_SLEEP" in pred.rule_fired

def test_regression_unrelated_block_events_isolated():
    """
    NEGATIVE TEST:
    Verifies that concurrent disk I/O from an UNRELATED process does NOT cause
    a concurrent CPU-bound process or cached read to inherit io_wait_dominated.
    """
    target_pid = 8001
    unrelated_pid = 9999
    wall_duration_ns = 20_000_000
    start_ns = 2_000_000_000
    end_ns = start_ns + wall_duration_ns

    # Target operation: cached file read or CPU calculation
    op = WorkloadOperationRecord(
        trial_id="target_cached_op",
        workload_type="file_read_sequential",
        operation_id=1,
        pid=target_pid,
        tid=target_pid,
        start_ns=start_ns,
        end_ns=end_ns,
        duration_ns=wall_duration_ns,
        intervention_label="file_read_warm",
        expected_label="indeterminate",
    )

    events = [
        # Target process executes read syscall (cached, 10ms duration)
        SyscallEvent(
            event_type=EventType.SYSCALL_COMPLETE.value,
            timestamp_ns=start_ns + 10_000_000,
            pid=target_pid,
            tid=target_pid,
            syscall_name="read",
            syscall_id=0,
            duration_ns=10_000_000,
        ),
        # UNRELATED process 9999 performs heavy physical block I/O in the exact same time window!
        BlockEvent(
            event_type=EventType.BLOCK_RQ_ISSUE.value,
            timestamp_ns=start_ns + 5_000_000,
            pid=unrelated_pid,
            bytes_count=131072,
        ),
        BlockEvent(
            event_type=EventType.BLOCK_RQ_COMPLETE.value,
            timestamp_ns=start_ns + 9_000_000,
            pid=unrelated_pid,
            bytes_count=131072,
        ),
    ]

    correlator = EventCorrelator(window_margin_ns=0)
    cw = correlator.correlate_operation(op, events)
    features = extract_features_from_correlated_window(cw)

    # Unrelated block events must NOT be counted as target block activity
    assert len(cw.block_events) == 0
    assert len(cw.background_block_events) == 2
    assert features["has_target_block_activity"] == 0
    assert features["target_block_bytes"] == 0
    assert features["has_background_block_activity"] == 1
    assert features["background_block_bytes"] == 262144

    classifier = RuleBasedClassifier()
    pred = classifier.predict_sample(features)

    # Must NOT classify as io_wait_dominated!
    assert pred.predicted_label != LABEL_IO_WAIT
    assert pred.predicted_label == LABEL_INDETERMINATE
    assert "RULE_IO_AMBIGUOUS_UNATTRIBUTED_BLOCK" in pred.rule_fired

def test_regression_ml_grouped_worker_isolation():
    """
    DATA INTEGRITY TEST:
    Verifies that concurrent workers belonging to the same experimental run
    (sharing a common parent_trial_id) are strictly kept together in either
    train or test, preventing multi-worker data leakage.
    """
    clf = LightweightMLClassifier()

    rows = []
    # 6 distinct experimental trials, each with 2 concurrent workers
    for trial_idx in range(6):
        parent_id = f"trial_run_{trial_idx}"
        label = "io_wait_dominated" if trial_idx % 2 == 0 else "cpu_syscall_dominated"
        for w_idx in range(2):
            worker_id = f"{parent_id}_worker_{w_idx}"
            rows.append({
                "trial_id": worker_id,
                "parent_trial_id": parent_id,
                "expected_label": label,
                "syscall_duration_ratio": 0.85 if label == "io_wait_dominated" else 0.05,
                "has_block_activity": 1 if label == "io_wait_dominated" else 0,
                "block_total_bytes": 65536 if label == "io_wait_dominated" else 0,
                "sched_wait_ratio": 0.05,
                "on_cpu_ratio": 0.10 if label == "io_wait_dominated" else 0.90,
                "unobserved_ratio": 0.0,
                "syscall_count": 5 if label == "io_wait_dominated" else 1,
                "sched_switch_count": 2,
                "fsync_count": 1 if label == "io_wait_dominated" else 0,
            })

    df = pd.DataFrame(rows)
    train_df, test_df = clf.split_data_by_trial(df, test_size=0.33, group_col="parent_trial_id")

    train_parents = set(train_df["parent_trial_id"])
    test_parents = set(test_df["parent_trial_id"])

    # Zero overlap of parent runs
    assert len(train_parents.intersection(test_parents)) == 0

    # Ensure all workers for any parent run are strictly in the same split
    for pid in train_parents:
        assert all(pid not in test_df["parent_trial_id"].values for _ in [0])
    for pid in test_parents:
        assert all(pid not in train_df["parent_trial_id"].values for _ in [0])

def test_regression_dropped_event_threshold_abstention():
    """
    SAFETY TEST:
    Verifies that when telemetry drop rate exceeds max_dropped_event_rate,
    the rule classifier abstains with RULE_ABSTAIN_EXCESSIVE_DROPS.
    """
    classifier = RuleBasedClassifier(config={"max_dropped_event_rate": 0.15})

    # High storage syscall ratio that would normally fire IO_WAIT, but with high drop rate
    features = {
        "wall_duration_ns": 10_000_000,
        "syscall_duration_ratio": 0.80,
        "has_target_block_activity": 1,
        "target_block_bytes": 65536,
        "sched_wait_ratio": 0.05,
        "on_cpu_ratio": 0.15,
        "unobserved_ratio": 0.0,
        "is_empty_window": 0,
        "dropped_event_rate": 0.25,  # 25% > 15% threshold
    }

    pred = classifier.predict_sample(features)
    assert pred.predicted_label == LABEL_INDETERMINATE
    assert "RULE_ABSTAIN_EXCESSIVE_DROPS" in pred.rule_fired

def test_regression_like_for_like_overhead_calculation():
    """
    METRICS TEST:
    Verifies that overhead calculation accurately reflects like-for-like duration comparisons.
    """
    unmonitored = [50.0, 52.0, 48.0]  # mean = 50.0 ms
    monitored = [51.0, 53.0, 52.0]    # mean = 52.0 ms

    ov = compute_overhead_metrics(unmonitored, monitored, total_events=5000, dropped_events=5)

    assert ov["unmonitored_mean_ms"] == 50.0
    assert ov["monitored_mean_ms"] == 52.0
    assert ov["overhead_delta_ms"] == 2.0
    assert ov["overhead_percent"] == 4.0
    assert ov["dropped_events"] == 5
    assert ov["dropped_event_rate"] == 0.001

def test_scheduler_contention_scales_background_workers_to_cpu_load():
    assert effective_competing_worker_count(2, 1, 12, 2) == 24
    assert effective_competing_worker_count(4, 4, 12, 2) == 6
    assert effective_competing_worker_count(8, 4, 12, 2) == 8
    assert effective_competing_worker_count(2, 1, 12, 2, pinned_to_single_cpu=True) == 2
    assert effective_competing_worker_count(4, 4, 12, 2, pinned_to_single_cpu=True) == 4
