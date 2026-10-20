"""
Unit tests for single-source baselines and feature isolation.
"""

import pytest
from stall_fingerprint.baselines import (
    SyscallOnlyClassifier,
    BlockOnlyClassifier,
    SchedulerOnlyClassifier,
)
from stall_fingerprint.classifier_rules import (
    LABEL_IO_WAIT,
    LABEL_SCHED_WAIT,
    LABEL_CPU_SYSCALL,
    LABEL_INDETERMINATE,
)

def test_syscall_only_baseline_isolation():
    clf = SyscallOnlyClassifier(syscall_ratio_thresh=0.40)
    # Even if sched_wait_ratio is 0.99, Syscall-only baseline must NOT predict scheduler_wait_dominated
    features = {
        "wall_duration_ns": 1000,
        "syscall_count": 5,
        "syscall_duration_ratio": 0.50,
        "sched_wait_ratio": 0.99,  # Should be ignored
        "has_block_activity": 1,   # Should be ignored
    }
    pred = clf.predict_sample(features)
    assert pred.predicted_label == LABEL_IO_WAIT
    assert pred.predicted_label != LABEL_SCHED_WAIT

def test_block_only_baseline_isolation():
    clf = BlockOnlyClassifier()
    # If block activity is present, predicts io_wait_dominated regardless of other signals
    features_with_block = {
        "has_block_activity": 1,
        "block_total_bytes": 4096,
        "syscall_duration_ratio": 0.0,
        "sched_wait_ratio": 0.0,
    }
    pred = clf.predict_sample(features_with_block)
    assert pred.predicted_label == LABEL_IO_WAIT

    # Without block activity, must abstain
    features_no_block = {
        "has_block_activity": 0,
        "block_total_bytes": 0,
    }
    pred_no = clf.predict_sample(features_no_block)
    assert pred_no.predicted_label == LABEL_INDETERMINATE

def test_scheduler_only_baseline_isolation():
    clf = SchedulerOnlyClassifier(sched_wait_thresh=0.40)
    # Even if syscall ratio is 0.90, Scheduler-only baseline must NOT predict io_wait_dominated
    features = {
        "sched_wait_ratio": 0.60,
        "syscall_duration_ratio": 0.90,  # Should be ignored
        "has_block_activity": 1,         # Should be ignored
    }
    pred = clf.predict_sample(features)
    assert pred.predicted_label == LABEL_SCHED_WAIT
    assert pred.predicted_label != LABEL_IO_WAIT
