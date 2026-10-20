"""
Unit tests for evaluation metrics and overhead accounting.
"""

import pytest
from stall_fingerprint.evaluation import (
    compute_classification_metrics,
    compute_overhead_metrics,
)
from stall_fingerprint.classifier_rules import (
    LABEL_IO_WAIT,
    LABEL_SCHED_WAIT,
    LABEL_CPU_SYSCALL,
    LABEL_INDETERMINATE,
)

def test_classification_metrics_perfect_predictions():
    y_true = [LABEL_IO_WAIT, LABEL_SCHED_WAIT, LABEL_CPU_SYSCALL, LABEL_INDETERMINATE]
    y_pred = [LABEL_IO_WAIT, LABEL_SCHED_WAIT, LABEL_CPU_SYSCALL, LABEL_INDETERMINATE]

    m = compute_classification_metrics(y_true, y_pred)
    assert m["overall_accuracy"] == 1.0
    assert m["macro_f1"] == 1.0
    assert m["abstention_rate"] == 0.25
    assert m["coverage"] == 0.75
    assert m["non_abstained_accuracy"] == 1.0
    assert m["per_class"][LABEL_IO_WAIT]["f1"] == 1.0

def test_classification_metrics_with_abstentions():
    y_true = [LABEL_IO_WAIT, LABEL_SCHED_WAIT, LABEL_CPU_SYSCALL]
    # Classifier predicts IO correctly, but abstains on sched and cpu
    y_pred = [LABEL_IO_WAIT, LABEL_INDETERMINATE, LABEL_INDETERMINATE]

    m = compute_classification_metrics(y_true, y_pred)
    assert m["total_samples"] == 3
    assert m["abstention_rate"] == round(2 / 3, 4)
    assert m["coverage"] == round(1 / 3, 4)
    # The 1 non-abstained prediction was correct
    assert m["non_abstained_accuracy"] == 1.0

def test_classification_metrics_empty_input():
    m = compute_classification_metrics([], [])
    assert m["total_samples"] == 0
    assert m["overall_accuracy"] == 0.0
    assert m["macro_f1"] == 0.0

def test_overhead_metrics_calculation():
    unmon = [100.0, 102.0, 98.0]  # mean = 100.0
    mon = [103.0, 105.0, 104.0]    # mean = 104.0

    ov = compute_overhead_metrics(unmon, mon, total_events=1000, dropped_events=10)

    assert ov["unmonitored_mean_ms"] == 100.0
    assert ov["monitored_mean_ms"] == 104.0
    assert ov["overhead_delta_ms"] == 4.0
    assert ov["overhead_percent"] == 4.0
    assert ov["total_events"] == 1000
    assert ov["dropped_events"] == 10
    assert 0.009 < ov["dropped_event_rate"] < 0.010
