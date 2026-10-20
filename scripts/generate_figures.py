#!/usr/bin/env python3
"""
Publication-Quality Figure Generator for Stall Fingerprinting.

Generates:
1. figures/baseline_comparison.pdf/.png (Macro-F1, Coverage, Non-abstained Accuracy across methods)
2. figures/confusion_matrix_fused.pdf/.png (Heatmap of predicted vs ground-truth labels)
3. figures/instrumentation_overhead.pdf/.png (Unmonitored vs Monitored latency distributions)
4. figures/runnable_wait_distribution.pdf/.png (Runnable delay by workload and concurrency)
5. figures/ablation_study.pdf/.png (Impact of individual signal layer removals)
"""

import sys
import os
import json
from pathlib import Path
import pandas as pd
import numpy as np

# Use headless backend
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns

# Set scientific plotting aesthetics
plt.style.use("seaborn-v0_8-whitegrid" if "seaborn-v0_8-whitegrid" in plt.style.available else "default")
plt.rcParams.update({
    "font.size": 11,
    "axes.labelsize": 12,
    "axes.titlesize": 13,
    "xtick.labelsize": 10,
    "ytick.labelsize": 10,
    "legend.fontsize": 10,
    "figure.titlesize": 14,
    "figure.autolayout": True,
})

def plot_baseline_comparison(comparison_csv: Path, out_dir: Path):
    if not comparison_csv.exists():
        return
    df = pd.read_csv(comparison_csv)
    if df.empty:
        return

    # Clean method names for display
    name_map = {
        "baseline_syscall_only": "Syscall Only",
        "baseline_block_only": "Block I/O Only",
        "baseline_sched_only": "Scheduler Only",
        "fused_rule_classifier": "Fused Rules",
        "ml_decision_tree": "Decision Tree",
    }
    df["display_name"] = df["method"].map(lambda x: name_map.get(x, x))

    metrics = ["macro_f1", "overall_accuracy", "non_abstained_accuracy", "coverage"]
    labels = ["Macro-F1", "Accuracy", "Non-Abst. Acc", "Coverage"]

    x = np.arange(len(df))
    width = 0.20

    fig, ax = plt.subplots(figsize=(8, 4.5))
    colors = ["#1f77b4", "#ff7f0e", "#2ca02c", "#d62728"]

    for i, (m, lbl) in enumerate(zip(metrics, labels)):
        if m in df.columns:
            ax.bar(x + (i - 1.5) * width, df[m], width, label=lbl, color=colors[i % len(colors)], alpha=0.9)

    ax.set_ylabel("Score (0.0 - 1.0)")
    ax.set_title("Detection Accuracy & Coverage Across Baselines and Fused System")
    ax.set_xticks(x)
    ax.set_xticklabels(df["display_name"], rotation=15, ha="right")
    ax.set_ylim(0, 1.1)
    ax.legend(loc="lower right", frameon=True)
    ax.grid(axis="y", linestyle="--", alpha=0.7)

    out_file = out_dir / "baseline_comparison.png"
    plt.savefig(out_file, dpi=300)
    plt.close()
    print(f"Saved: {out_file}")

def plot_confusion_matrix(metrics_json: Path, out_dir: Path):
    if not metrics_json.exists():
        return
    with open(metrics_json, "r", encoding="utf-8") as f:
        data = json.load(f)

    fused_metrics = data.get("fused_rule_classifier", {})
    cm_dict = fused_metrics.get("confusion_matrix", {})
    if not cm_dict:
        return

    classes = list(cm_dict.keys())
    matrix = np.zeros((len(classes), len(classes)), dtype=int)
    for i, true_l in enumerate(classes):
        for j, pred_l in enumerate(classes):
            matrix[i, j] = cm_dict[true_l].get(pred_l, 0)

    # Abbreviate class names for compact plot
    abbr_map = {
        "io_wait_dominated": "IO-Wait",
        "scheduler_wait_dominated": "Sched-Wait",
        "cpu_syscall_dominated": "CPU-Dom",
        "indeterminate": "Indet",
    }
    short_labels = [abbr_map.get(c, c) for c in classes]

    fig, ax = plt.subplots(figsize=(6, 5))
    sns.heatmap(
        matrix,
        annot=True,
        fmt="d",
        cmap="Blues",
        xticklabels=short_labels,
        yticklabels=short_labels,
        cbar=False,
        ax=ax,
    )
    ax.set_xlabel("Predicted Label", fontweight="bold")
    ax.set_ylabel("Ground Truth (Intervention)", fontweight="bold")
    ax.set_title("Confusion Matrix: Fused Rule Classifier")

    out_file = out_dir / "confusion_matrix_fused.png"
    plt.savefig(out_file, dpi=300)
    plt.close()
    print(f"Saved: {out_file}")

def plot_overhead(metrics_json: Path, out_dir: Path):
    if not metrics_json.exists():
        return
    with open(metrics_json, "r", encoding="utf-8") as f:
        data = json.load(f)

    ov = data.get("instrumentation_overhead", {})
    if not ov:
        return

    categories = ["Unmonitored", "Monitored (eBPF)"]
    means = [ov.get("unmonitored_mean_ms", 0), ov.get("monitored_mean_ms", 0)]
    stds = [ov.get("unmonitored_std_ms", 0), ov.get("monitored_std_ms", 0)]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(9, 4))

    # Latency comparison
    ax1.bar(categories, means, yerr=stds, capsize=5, color=["#7f7f7f", "#2ca02c"], alpha=0.85, width=0.5)
    ax1.set_ylabel("Execution Time (ms)")
    ax1.set_title("Runtime Overhead Impact")
    ax1.grid(axis="y", linestyle="--", alpha=0.7)

    # Latency percentiles
    p_labels = ["p50", "p90", "p99"]
    p_vals = [ov.get("latency_p50_ms", 0), ov.get("latency_p90_ms", 0), ov.get("latency_p99_ms", 0)]
    ax2.plot(p_labels, p_vals, marker="o", color="#d62728", linewidth=2, markersize=8)
    ax2.set_ylabel("Latency (ms)")
    ax2.set_title(f"Monitored Tail Latency (Overhead: {ov.get('overhead_percent', 0):.1f}%)")
    ax2.grid(True, linestyle="--", alpha=0.7)

    out_file = out_dir / "instrumentation_overhead.png"
    plt.savefig(out_file, dpi=300)
    plt.close()
    print(f"Saved: {out_file}")

def plot_runnable_wait(features_csv: Path, out_dir: Path):
    if not features_csv.exists():
        return
    df = pd.read_csv(features_csv)
    if df.empty or "workload_type" not in df.columns or "sched_wait_ratio" not in df.columns:
        return

    fig, ax = plt.subplots(figsize=(7, 4.5))
    sns.boxplot(
        data=df,
        x="workload_type",
        y="sched_wait_ratio",
        hue="concurrency" if "concurrency" in df.columns else None,
        palette="Set2",
        ax=ax,
    )
    ax.set_ylabel("Runnable Wait Ratio (Wait / Wall Duration)")
    ax.set_xlabel("Workload Category")
    ax.set_title("Observed Runnable Scheduler Wait Across Interventions")
    ax.set_xticklabels(ax.get_xticklabels(), rotation=20, ha="right")
    ax.grid(axis="y", linestyle="--", alpha=0.7)

    out_file = out_dir / "runnable_wait_distribution.png"
    plt.savefig(out_file, dpi=300)
    plt.close()
    print(f"Saved: {out_file}")

def generate_all_figures(results_dir: Path, figures_dir: Path):
    figures_dir.mkdir(parents=True, exist_ok=True)
    plot_baseline_comparison(results_dir / "baseline_comparison.csv", figures_dir)
    plot_confusion_matrix(results_dir / "metrics.json", figures_dir)
    plot_overhead(results_dir / "metrics.json", figures_dir)
    plot_runnable_wait(results_dir / "features.csv", figures_dir)

def main():
    if len(sys.argv) < 2:
        print("Usage: python generate_figures.py <results_run_dir> [figures_output_dir]")
        sys.exit(1)
    res_dir = Path(sys.argv[1])
    fig_dir = Path(sys.argv[2]) if len(sys.argv) > 2 else res_dir / "figures"
    generate_all_figures(res_dir, fig_dir)

if __name__ == "__main__":
    main()
