"""
Unit tests for the transparent rule-based classifier.
"""

import pytest
from stall_fingerprint.classifier_rules import (
    RuleBasedClassifier,
    LABEL_IO_WAIT,
    LABEL_SCHED_WAIT,
    LABEL_CPU_SYSCALL,
    LABEL_INDETERMINATE,
)

@pytest.fixture
def classifier():
    return RuleBasedClassifier()

def test_classify_io_wait(classifier):
    features = {
        "wall_duration_ns": 10_000_000,
        "syscall_duration_ratio": 0.65,
        "has_block_activity": 1,
        "block_total_bytes": 65536,
        "fsync_count": 1,
        "sched_wait_ratio": 0.05,
        "on_cpu_ratio": 0.30,
        "unobserved_ratio": 0.0,
        "is_empty_window": 0,
    }
    pred = classifier.predict_sample(features)
    assert pred.predicted_label == LABEL_IO_WAIT
    assert pred.confidence >= 0.70
    assert "RULE_IO_WAIT_FUSED" in pred.rule_fired

def test_classify_sched_wait(classifier):
    features = {
        "wall_duration_ns": 10_000_000,
        "syscall_duration_ratio": 0.05,
        "has_block_activity": 0,
        "block_total_bytes": 0,
        "fsync_count": 0,
        "sched_wait_ratio": 0.75,
        "on_cpu_ratio": 0.20,
        "unobserved_ratio": 0.0,
        "is_empty_window": 0,
    }
    pred = classifier.predict_sample(features)
    assert pred.predicted_label == LABEL_SCHED_WAIT
    assert pred.confidence >= 0.70
    assert "RULE_SCHED_WAIT_DOMINATED" in pred.rule_fired

def test_classify_cpu_syscall(classifier):
    features = {
        "wall_duration_ns": 10_000_000,
        "syscall_duration_ratio": 0.05,
        "has_block_activity": 0,
        "block_total_bytes": 0,
        "fsync_count": 0,
        "sched_wait_ratio": 0.05,
        "on_cpu_ratio": 0.90,
        "unobserved_ratio": 0.0,
        "is_empty_window": 0,
    }
    pred = classifier.predict_sample(features)
    assert pred.predicted_label == LABEL_CPU_SYSCALL
    assert pred.confidence >= 0.80
    assert "RULE_CPU_PROCESSING_DOMINATED" in pred.rule_fired

def test_classify_indeterminate_empty_window(classifier):
    features = {
        "wall_duration_ns": 10_000_000,
        "syscall_duration_ratio": 0.0,
        "has_block_activity": 0,
        "block_total_bytes": 0,
        "fsync_count": 0,
        "sched_wait_ratio": 0.0,
        "on_cpu_ratio": 0.0,
        "unobserved_ratio": 1.0,
        "is_empty_window": 1,
    }
    pred = classifier.predict_sample(features)
    assert pred.predicted_label == LABEL_INDETERMINATE
    assert "RULE_ABSTAIN_UNOBSERVED_TELEMETRY" in pred.rule_fired

def test_classify_indeterminate_cached_io(classifier):
    features = {
        "wall_duration_ns": 10_000_000,
        "syscall_duration_ratio": 0.50,
        "has_block_activity": 0,
        "block_total_bytes": 0,
        "fsync_count": 0,
        "sched_wait_ratio": 0.05,
        "on_cpu_ratio": 0.45,
        "unobserved_ratio": 0.0,
        "is_empty_window": 0,
    }
    pred = classifier.predict_sample(features)
    assert pred.predicted_label == LABEL_INDETERMINATE
    assert "RULE_IO_AMBIGUOUS_CACHED" in pred.rule_fired
