"""
Unit tests for data validation, grouped train/test splits, and ML classifier.
"""

import pytest
import pandas as pd
from stall_fingerprint.classifier_ml import LightweightMLClassifier, ML_FEATURE_COLS

def test_ml_data_sufficiency_check():
    clf = LightweightMLClassifier(min_samples_per_class=2)

    # Empty df
    empty_df = pd.DataFrame()
    suff, _ = clf.check_data_sufficiency(empty_df)
    assert suff is False

    # Too few samples
    small_df = pd.DataFrame({
        "expected_label": ["io_wait_dominated", "cpu_syscall_dominated"],
    })
    suff, _ = clf.check_data_sufficiency(small_df)
    assert suff is False

def test_ml_grouped_train_test_split():
    clf = LightweightMLClassifier()
    # Create synthetic dataset with 4 trials
    rows = []
    for t_idx in range(4):
        trial_id = f"trial_{t_idx}"
        label = "io_wait_dominated" if t_idx % 2 == 0 else "cpu_syscall_dominated"
        for op in range(3):
            rows.append({
                "trial_id": trial_id,
                "expected_label": label,
                "syscall_duration_ratio": 0.8 if label == "io_wait_dominated" else 0.05,
                "has_block_activity": 1 if label == "io_wait_dominated" else 0,
                "block_total_bytes": 4096 if label == "io_wait_dominated" else 0,
                "sched_wait_ratio": 0.05,
                "on_cpu_ratio": 0.15 if label == "io_wait_dominated" else 0.90,
                "unobserved_ratio": 0.0,
                "syscall_count": 5 if label == "io_wait_dominated" else 1,
                "sched_switch_count": 2,
                "fsync_count": 1 if label == "io_wait_dominated" else 0,
            })
    df = pd.DataFrame(rows)

    train_df, test_df = clf.split_data_by_trial(df, test_size=0.25)

    # Verify strict trial isolation
    train_trials = set(train_df["trial_id"])
    test_trials = set(test_df["trial_id"])
    assert len(train_trials.intersection(test_trials)) == 0

    # Test training and prediction
    fitted = clf.fit(train_df, target_col="expected_label")
    assert fitted is True
    assert clf.is_fitted is True

    preds = clf.predict(test_df)
    assert len(preds) == len(test_df)

    importances = clf.get_feature_importances()
    assert len(importances) == len(ML_FEATURE_COLS)
    rules_text = clf.export_rules()
    assert "class:" in rules_text
