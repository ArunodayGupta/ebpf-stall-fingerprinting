#!/usr/bin/env python3
"""
Ablation Study Runner for Stall Fingerprinting.

Evaluates:
1. Contribution of individual telemetry layers (No Block, No Scheduler, No Syscall)
2. Window margin variations (0ms, 2ms, 5ms, 10ms, 20ms)
3. Target attribution ablation (Attributed PID vs Naive All-Window)
4. Cache state analysis (Cold vs Warm cached reads)
"""

import sys
import os
import json
import argparse
from pathlib import Path
import pandas as pd

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))

from stall_fingerprint.classifier_rules import (
    RuleBasedClassifier,
    LABEL_IO_WAIT,
    LABEL_SCHED_WAIT,
    LABEL_CPU_SYSCALL,
    LABEL_INDETERMINATE,
    RulePrediction,
)
from stall_fingerprint.event_schema import EventReader
from stall_fingerprint.correlation import EventCorrelator
from stall_fingerprint.feature_extraction import extract_features_table
from workloads.workload_utils import WorkloadOperationRecord
from stall_fingerprint.evaluation import compute_classification_metrics

def _row_int(row: pd.Series, key: str, default: int = 0) -> int:
    value = row.get(key, default)
    return int(value) if pd.notna(value) else default

class AblationClassifier:
    """Evaluates classifier behavior with targeted feature masks."""

    def __init__(self, mode: str, base_classifier: RuleBasedClassifier):
        self.mode = mode
        self.base_classifier = base_classifier

    def predict_sample(self, features: dict) -> RulePrediction:
        feat_copy = dict(features)
        if self.mode == "no_block":
            feat_copy["has_block_activity"] = 0
            feat_copy["has_target_block_activity"] = 0
            feat_copy["block_total_bytes"] = 0
            feat_copy["target_block_bytes"] = 0
            feat_copy["block_issue_count"] = 0
            feat_copy["block_complete_count"] = 0
        elif self.mode == "no_sched":
            feat_copy["sched_wait_ratio"] = 0.0
            feat_copy["runnable_wait_ns"] = 0
            feat_copy["sched_switch_count"] = 0
            feat_copy["off_cpu_blocked_ratio"] = 0.0
        elif self.mode == "no_syscall":
            feat_copy["syscall_duration_ratio"] = 0.0
            feat_copy["non_overlap_syscall_ns"] = 0
            feat_copy["fsync_count"] = 0
            feat_copy["syscall_count"] = 0
            feat_copy["sleep_syscall_ratio"] = 0.0

        return self.base_classifier.predict_sample(feat_copy)

    def predict_dataframe(self, df: pd.DataFrame) -> list:
        return [self.predict_sample(r.to_dict()).predicted_label for _, r in df.iterrows()]

def run_telemetry_layer_ablations(df: pd.DataFrame, base_clf: RuleBasedClassifier) -> pd.DataFrame:
    y_true = df["expected_label"].tolist()

    configurations = [
        ("fused_full", "Fused System (All Layers)"),
        ("no_block", "Ablation: No Block I/O"),
        ("no_sched", "Ablation: No Scheduler Telemetry"),
        ("no_syscall", "Ablation: No Syscall Durations"),
    ]

    results = []
    for mode_id, display_name in configurations:
        if mode_id == "fused_full":
            preds = [base_clf.predict_sample(r.to_dict()).predicted_label for _, r in df.iterrows()]
        else:
            ablated_clf = AblationClassifier(mode=mode_id, base_classifier=base_clf)
            preds = ablated_clf.predict_dataframe(df)

        m = compute_classification_metrics(y_true, preds)
        results.append({
            "ablation_type": "telemetry_layers",
            "condition": mode_id,
            "display_name": display_name,
            "macro_f1": m["macro_f1"],
            "overall_accuracy": m["overall_accuracy"],
            "abstention_rate": m["abstention_rate"],
            "coverage": m["coverage"],
            "non_abstained_accuracy": m["non_abstained_accuracy"],
            "io_wait_f1": m["per_class"].get(LABEL_IO_WAIT, {}).get("f1", 0.0),
            "sched_wait_f1": m["per_class"].get(LABEL_SCHED_WAIT, {}).get("f1", 0.0),
            "cpu_f1": m["per_class"].get(LABEL_CPU_SYSCALL, {}).get("f1", 0.0),
        })
    return pd.DataFrame(results)

def run_window_margin_ablations(raw_events_path: Path, workload_runs_csv: Path, base_clf: RuleBasedClassifier) -> pd.DataFrame:
    if not raw_events_path.exists() or not workload_runs_csv.exists():
        return pd.DataFrame()

    runs_df = pd.read_csv(workload_runs_csv)
    records = []
    for _, row in runs_df.iterrows():
        records.append(WorkloadOperationRecord(
            trial_id=row["trial_id"],
            workload_type=row["workload_type"],
            operation_id=int(row["operation_id"]),
            pid=int(row["pid"]),
            tid=int(row.get("tid", row["pid"])),
            start_ns=int(row["start_ns"]),
            end_ns=int(row["end_ns"]),
            duration_ns=int(row["duration_ns"]),
            intervention_label=row["intervention_label"],
            expected_label=row["expected_label"],
            concurrency=int(row.get("concurrency", 1)),
            target_comm=row.get("target_comm", "") if isinstance(row.get("target_comm", ""), str) else "",
            dropped_events_count=_row_int(row, "dropped_events_count"),
            total_events_emitted=_row_int(row, "total_events_emitted"),
        ))

    events = EventReader(raw_events_path).read_all()
    margins_ms = [0, 2, 5, 10, 20]
    results = []

    for m_ms in margins_ms:
        margin_ns = m_ms * 1_000_000
        correlator = EventCorrelator(window_margin_ns=margin_ns)
        cw_list = correlator.correlate_all(records, events)
        feat_df = extract_features_table(cw_list)
        if feat_df.empty:
            continue

        y_true = feat_df["expected_label"].tolist()
        preds, _ = base_clf.predict_dataframe(feat_df)
        m = compute_classification_metrics(y_true, preds)
        results.append({
            "ablation_type": "window_margin",
            "condition": f"margin_{m_ms}ms",
            "display_name": f"Window Margin: {m_ms} ms",
            "macro_f1": m["macro_f1"],
            "overall_accuracy": m["overall_accuracy"],
            "abstention_rate": m["abstention_rate"],
            "coverage": m["coverage"],
            "non_abstained_accuracy": m["non_abstained_accuracy"],
            "io_wait_f1": m["per_class"].get(LABEL_IO_WAIT, {}).get("f1", 0.0),
            "sched_wait_f1": m["per_class"].get(LABEL_SCHED_WAIT, {}).get("f1", 0.0),
            "cpu_f1": m["per_class"].get(LABEL_CPU_SYSCALL, {}).get("f1", 0.0),
        })

    return pd.DataFrame(results)

def run_attribution_ablation(raw_events_path: Path, workload_runs_csv: Path, base_clf: RuleBasedClassifier) -> pd.DataFrame:
    if not raw_events_path.exists() or not workload_runs_csv.exists():
        return pd.DataFrame()

    runs_df = pd.read_csv(workload_runs_csv)
    records = []
    for _, row in runs_df.iterrows():
        records.append(WorkloadOperationRecord(
            trial_id=row["trial_id"],
            workload_type=row["workload_type"],
            operation_id=int(row["operation_id"]),
            pid=int(row["pid"]),
            tid=int(row.get("tid", row["pid"])),
            start_ns=int(row["start_ns"]),
            end_ns=int(row["end_ns"]),
            duration_ns=int(row["duration_ns"]),
            intervention_label=row["intervention_label"],
            expected_label=row["expected_label"],
            concurrency=int(row.get("concurrency", 1)),
            target_comm=row.get("target_comm", "") if isinstance(row.get("target_comm", ""), str) else "",
            dropped_events_count=_row_int(row, "dropped_events_count"),
            total_events_emitted=_row_int(row, "total_events_emitted"),
        ))

    events = EventReader(raw_events_path).read_all()
    results = []

    for mode, display in [("attributed", "PID-Attributed Block Events"), ("all_window", "Naive All-Window Block Events")]:
        correlator = EventCorrelator(window_margin_ns=5_000_000, attribution_mode=mode)
        cw_list = correlator.correlate_all(records, events)
        feat_df = extract_features_table(cw_list)
        if feat_df.empty:
            continue

        y_true = feat_df["expected_label"].tolist()
        preds, _ = base_clf.predict_dataframe(feat_df)
        m = compute_classification_metrics(y_true, preds)
        results.append({
            "ablation_type": "attribution_granularity",
            "condition": mode,
            "display_name": display,
            "macro_f1": m["macro_f1"],
            "overall_accuracy": m["overall_accuracy"],
            "abstention_rate": m["abstention_rate"],
            "coverage": m["coverage"],
            "non_abstained_accuracy": m["non_abstained_accuracy"],
            "io_wait_f1": m["per_class"].get(LABEL_IO_WAIT, {}).get("f1", 0.0),
            "sched_wait_f1": m["per_class"].get(LABEL_SCHED_WAIT, {}).get("f1", 0.0),
            "cpu_f1": m["per_class"].get(LABEL_CPU_SYSCALL, {}).get("f1", 0.0),
        })

    return pd.DataFrame(results)

def run_ablation_study(features_csv: Path, output_dir: Path):
    if not features_csv.exists():
        print(f"Error: {features_csv} not found.")
        return

    df = pd.read_csv(features_csv)
    if df.empty or "expected_label" not in df.columns:
        print("Error: features table empty or missing expected_label column.")
        return

    base_clf = RuleBasedClassifier()
    output_dir.mkdir(parents=True, exist_ok=True)

    # 1. Telemetry layer ablations
    layer_df = run_telemetry_layer_ablations(df, base_clf)

    # 2. Window margin and attribution ablations (if raw events exist in parent dir)
    parent_dir = features_csv.parent
    raw_ev = parent_dir / "raw_events.jsonl"
    workload_csv = parent_dir / "workload_runs.csv"

    margin_df = run_window_margin_ablations(raw_ev, workload_csv, base_clf)
    attrib_df = run_attribution_ablation(raw_ev, workload_csv, base_clf)

    all_ablations = pd.concat([layer_df, margin_df, attrib_df], ignore_index=True)
    out_file = output_dir / "ablation_study.csv"
    all_ablations.to_csv(out_file, index=False)

    print("=" * 70)
    print("  Comprehensive Ablation Study Summary:")
    print("=" * 70)
    print(all_ablations[["display_name", "macro_f1", "overall_accuracy", "abstention_rate", "coverage"]].to_string(index=False))
    print(f"\nSaved ablation results to {out_file}")

def main():
    parser = argparse.ArgumentParser(description="Stall Fingerprinting Ablation Evaluator")
    parser.add_argument("features_csv", help="Path to features.csv")
    parser.add_argument("--output-dir", default=None, help="Output directory")
    args = parser.parse_args()

    feat_path = Path(args.features_csv)
    out_dir = Path(args.output_dir) if args.output_dir else feat_path.parent
    run_ablation_study(feat_path, out_dir)

if __name__ == "__main__":
    main()
