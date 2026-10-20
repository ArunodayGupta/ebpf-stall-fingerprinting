"""
Evaluation and Metrics Engine for Stall Fingerprinting.

Calculates:
- Macro-F1, per-class Precision and Recall
- Confusion matrices with full taxonomy alignment
- Abstention rate (indeterminate rate) and non-abstained coverage/accuracy
- Latency quantiles (p50, p90, p99) and duration estimation error
- Instrumentation overhead (wall-clock delta, throughput, dropped event rate)
"""

import numpy as np
import pandas as pd
from typing import Dict, Any, List, Optional, Tuple
from sklearn.metrics import precision_recall_fscore_support, confusion_matrix, accuracy_score
from stall_fingerprint.classifier_rules import VALID_LABELS, LABEL_INDETERMINATE

def compute_classification_metrics(
    y_true: List[str],
    y_pred: List[str],
    labels: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Computes comprehensive classification metrics with explicit handling of abstentions and missing classes.
    """
    all_labels = labels or VALID_LABELS
    y_true = list(y_true)
    y_pred = list(y_pred)
    total_samples = len(y_true)

    if total_samples == 0:
        return {
            "total_samples": 0,
            "macro_f1": 0.0,
            "overall_accuracy": 0.0,
            "abstention_rate": 0.0,
            "coverage": 0.0,
            "non_abstained_accuracy": 0.0,
            "per_class": {},
            "confusion_matrix": {},
        }

    # Confusion matrix
    cm = confusion_matrix(y_true, y_pred, labels=all_labels)
    cm_dict = {}
    for i, true_l in enumerate(all_labels):
        cm_dict[true_l] = {}
        for j, pred_l in enumerate(all_labels):
            cm_dict[true_l][pred_l] = int(cm[i, j])

    # Overall accuracy
    acc = accuracy_score(y_true, y_pred)

    # Per-class precision, recall, f1
    p, r, f1, support = precision_recall_fscore_support(
        y_true,
        y_pred,
        labels=all_labels,
        zero_division=0,
    )

    per_class = {}
    for idx, l in enumerate(all_labels):
        per_class[l] = {
            "precision": round(float(p[idx]), 4),
            "recall": round(float(r[idx]), 4),
            "f1": round(float(f1[idx]), 4),
            "support": int(support[idx]),
        }

    # Macro-F1 across active ground truth classes
    active_f1s = [per_class[l]["f1"] for l in all_labels if per_class[l]["support"] > 0]
    macro_f1 = float(np.mean(active_f1s)) if active_f1s else 0.0

    # Abstention / Indeterminate statistics
    indeterminate_count = sum(1 for yp in y_pred if yp == LABEL_INDETERMINATE)
    abstention_rate = indeterminate_count / total_samples
    coverage = 1.0 - abstention_rate

    # Non-abstained accuracy
    non_abstained_indices = [i for i, yp in enumerate(y_pred) if yp != LABEL_INDETERMINATE]
    if non_abstained_indices:
        na_true = [y_true[i] for i in non_abstained_indices]
        na_pred = [y_pred[i] for i in non_abstained_indices]
        na_acc = accuracy_score(na_true, na_pred)
    else:
        na_acc = 0.0

    return {
        "total_samples": total_samples,
        "overall_accuracy": round(acc, 4),
        "macro_f1": round(macro_f1, 4),
        "abstention_rate": round(abstention_rate, 4),
        "coverage": round(coverage, 4),
        "non_abstained_accuracy": round(na_acc, 4),
        "per_class": per_class,
        "confusion_matrix": cm_dict,
    }

def compute_overhead_metrics(
    unmonitored_durations_ms: List[float],
    monitored_durations_ms: List[float],
    total_events: int = 0,
    dropped_events: int = 0,
) -> Dict[str, Any]:
    """
    Quantifies the tracing probe effect by comparing unmonitored vs monitored executions.
    """
    unmon_arr = np.array(unmonitored_durations_ms) if unmonitored_durations_ms else np.array([1.0])
    mon_arr = np.array(monitored_durations_ms) if monitored_durations_ms else np.array([1.0])

    unmon_mean = float(np.mean(unmon_arr))
    mon_mean = float(np.mean(mon_arr))

    overhead_delta_ms = mon_mean - unmon_mean
    overhead_pct = (overhead_delta_ms / unmon_mean) * 100.0 if unmon_mean > 0 else 0.0

    # Latency quantiles
    p50 = float(np.percentile(mon_arr, 50))
    p90 = float(np.percentile(mon_arr, 90))
    p99 = float(np.percentile(mon_arr, 99))

    dropped_rate = (dropped_events / (total_events + dropped_events)) if (total_events + dropped_events) > 0 else 0.0

    return {
        "unmonitored_mean_ms": round(unmon_mean, 2),
        "unmonitored_std_ms": round(float(np.std(unmon_arr)), 2),
        "monitored_mean_ms": round(mon_mean, 2),
        "monitored_std_ms": round(float(np.std(mon_arr)), 2),
        "overhead_delta_ms": round(overhead_delta_ms, 2),
        "overhead_percent": round(overhead_pct, 2),
        "latency_p50_ms": round(p50, 2),
        "latency_p90_ms": round(p90, 2),
        "latency_p99_ms": round(p99, 2),
        "total_events": total_events,
        "dropped_events": dropped_events,
        "dropped_event_rate": round(dropped_rate, 4),
    }
