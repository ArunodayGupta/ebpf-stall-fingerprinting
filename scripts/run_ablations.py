#!/usr/bin/env python3
"""
Ablation Study Runner for Stall Fingerprinting.

Evaluates the contribution of individual telemetry layers:
1. Full Fused Classifier (Syscall + Block + Scheduler)
2. Ablation: No Block I/O telemetry
3. Ablation: No Scheduler telemetry
4. Ablation: No Syscall duration telemetry

Quantifies drop in Macro-F1 and increase in abstention/error when individual signals are removed.
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
from stall_fingerprint.evaluation import compute_classification_metrics

class AblationClassifier:
    """Evaluates classifier behavior with targeted feature masks."""

    def __init__(self, mode: str, base_classifier: RuleBasedClassifier):
        self.mode = mode
        self.base_classifier = base_classifier

    def predict_sample(self, features: dict) -> RulePrediction:
        feat_copy = dict(features)
        if self.mode == "no_block":
            feat_copy["has_block_activity"] = 0
            feat_copy["block_total_bytes"] = 0
            feat_copy["block_issue_count"] = 0
            feat_copy["block_complete_count"] = 0
        elif self.mode == "no_sched":
            feat_copy["sched_wait_ratio"] = 0.0
            feat_copy["runnable_wait_ns"] = 0
            feat_copy["sched_switch_count"] = 0
        elif self.mode == "no_syscall":
            feat_copy["syscall_duration_ratio"] = 0.0
            feat_copy["non_overlap_syscall_ns"] = 0
            feat_copy["fsync_count"] = 0
            feat_copy["syscall_count"] = 0

        return self.base_classifier.predict_sample(feat_copy)

    def predict_dataframe(self, df: pd.DataFrame) -> list:
        return [self.predict_sample(r.to_dict()).predicted_label for _, r in df.iterrows()]

def run_ablation_study(features_csv: Path, output_dir: Path):
    if not features_csv.exists():
        print(f"Error: {features_csv} not found.")
        return

    df = pd.read_csv(features_csv)
    if df.empty or "expected_label" not in df.columns:
        print("Error: features table empty or missing expected_label column.")
        return

    y_true = df["expected_label"].tolist()
    base_clf = RuleBasedClassifier()

    configurations = [
        ("fused_full", "Fused System (All Layers)"),
        ("no_block", "Ablation: No Block I/O"),
        ("no_sched", "Ablation: No Scheduler Telemetry"),
        ("no_syscall", "Ablation: No Syscall Durations"),
    ]

    ablation_results = []
    for mode_id, display_name in configurations:
        if mode_id == "fused_full":
            preds = [base_clf.predict_sample(r.to_dict()).predicted_label for _, r in df.iterrows()]
        else:
            ablated_clf = AblationClassifier(mode=mode_id, base_classifier=base_clf)
            preds = ablated_clf.predict_dataframe(df)

        m = compute_classification_metrics(y_true, preds)
        ablation_results.append({
            "ablation_mode": mode_id,
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

    abl_df = pd.DataFrame(ablation_results)
    output_dir.mkdir(parents=True, exist_ok=True)
    out_file = output_dir / "ablation_study.csv"
    abl_df.to_csv(out_file, index=False)
    print("=" * 60)
    print("  Ablation Study Summary:")
    print("=" * 60)
    print(abl_df[["display_name", "macro_f1", "overall_accuracy", "abstention_rate", "coverage"]].to_string(index=False))
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
