#!/usr/bin/env python3
"""
Report Data & LaTeX Table Generator.

Extracts data from experiment results (metrics.json, baseline_comparison.csv)
and exports clean LaTeX tables and definition macros for direct inclusion in report/main.tex.
"""

import sys
import os
import json
from pathlib import Path
import pandas as pd

def generate_latex_tables(results_dir: Path, report_dir: Path):
    tables_dir = report_dir / "tables"
    tables_dir.mkdir(parents=True, exist_ok=True)

    metrics_file = results_dir / "metrics.json"
    comparison_file = results_dir / "baseline_comparison.csv"
    macros_file = report_dir / "macros.tex"

    if not metrics_file.exists() or not comparison_file.exists():
        print(f"Metrics not found in {results_dir}. Generating placeholder tables.")
        _write_placeholder_tables(tables_dir, macros_file)
        return

    with open(metrics_file, "r", encoding="utf-8") as f:
        metrics = json.load(f)

    comp_df = pd.read_csv(comparison_file)

    # 1. Generate Baseline Comparison Table LaTeX
    table_lines = [
        r"\begin{table}[t]",
        r"\centering",
        r"\caption{Comparison of Classification Performance Across Single-Source Baselines and Fused System}",
        r"\label{tab:baseline_comparison}",
        r"\resizebox{\columnwidth}{!}{%",
        r"\begin{tabular}{lcccccc}",
        r"\hline",
        r"\textbf{Method} & \textbf{Macro-F1} & \textbf{Accuracy} & \textbf{Coverage} & \textbf{Non-Abst. Acc} & \textbf{I/O F1} & \textbf{Sched F1} \\",
        r"\hline",
    ]

    name_map = {
        "baseline_syscall_only": "Syscall Duration Only",
        "baseline_block_only": "Block-Layer Only",
        "baseline_sched_only": "Scheduler Wait Only",
        "fused_rule_classifier": "\\textbf{Fused Rule Classifier}",
        "ml_decision_tree": "Decision Tree (ML)",
    }

    for _, row in comp_df.iterrows():
        m_name = name_map.get(row["method"], row["method"])
        f1 = f"{row['macro_f1']:.3f}"
        acc = f"{row['overall_accuracy']:.3f}"
        cov = f"{row['coverage']*100:.1f}\\%"
        na_acc = f"{row['non_abstained_accuracy']:.3f}"
        io_f1 = f"{row['io_wait_f1']:.3f}"
        sc_f1 = f"{row['sched_wait_f1']:.3f}"
        table_lines.append(f"{m_name} & {f1} & {acc} & {cov} & {na_acc} & {io_f1} & {sc_f1} \\\\")

    table_lines.extend([
        r"\hline",
        r"\end{tabular}",
        r"}",
        r"\end{table}",
    ])

    with open(tables_dir / "baseline_table.tex", "w", encoding="utf-8") as f:
        f.write("\n".join(table_lines) + "\n")

    # 2. Generate Overhead Table
    ov = metrics.get("instrumentation_overhead", {})
    ov_lines = [
        r"\begin{table}[t]",
        r"\centering",
        r"\caption{eBPF Instrumentation Overhead and Latency Profile}",
        r"\label{tab:overhead_profile}",
        r"\begin{tabular}{lcc}",
        r"\hline",
        r"\textbf{Metric} & \textbf{Unmonitored} & \textbf{Monitored (eBPF)} \\",
        r"\hline",
        f"Mean Duration (ms) & {ov.get('unmonitored_mean_ms', 0):.2f} $\\pm$ {ov.get('unmonitored_std_ms', 0):.2f} & {ov.get('monitored_mean_ms', 0):.2f} $\\pm$ {ov.get('monitored_std_ms', 0):.2f} \\\\",
        f"Overhead Delta & --- & {ov.get('overhead_delta_ms', 0):.2f} ms ({ov.get('overhead_percent', 0):.1f}\\%) \\\\",
        f"p50 Tail Latency & --- & {ov.get('latency_p50_ms', 0):.2f} ms \\\\",
        f"p99 Tail Latency & --- & {ov.get('latency_p99_ms', 0):.2f} ms \\\\",
        f"Dropped Event Rate & --- & {ov.get('dropped_event_rate', 0):.4f} \\\\",
        r"\hline",
        r"\end{tabular}",
        r"\end{table}",
    ]
    with open(tables_dir / "overhead_table.tex", "w", encoding="utf-8") as f:
        f.write("\n".join(ov_lines) + "\n")

    # 3. Export LaTeX Macros
    fused_m = metrics.get("fused_rule_classifier", {})
    macro_f1_val = fused_m.get("macro_f1", 0.0)
    acc_val = fused_m.get("overall_accuracy", 0.0)
    cov_val = fused_m.get("coverage", 0.0) * 100.0
    ov_pct = ov.get("overhead_percent", 0.0)

    macros = [
        f"\\newcommand{{\\ValFusedMacroF1}}{{{macro_f1_val:.3f}}}",
        f"\\newcommand{{\\ValFusedAccuracy}}{{{acc_val:.3f}}}",
        f"\\newcommand{{\\ValFusedCoverage}}{{{cov_val:.1f}\\%}}",
        f"\\newcommand{{\\ValOverheadPercent}}{{{ov_pct:.1f}\\%}}",
    ]
    with open(macros_file, "w", encoding="utf-8") as f:
        f.write("\n".join(macros) + "\n")

    print(f"Report tables and macros exported to {report_dir}")

def _write_placeholder_tables(tables_dir: Path, macros_file: Path):
    table_lines = [
        r"\begin{table}[t]",
        r"\centering",
        r"\caption{Comparison Across Baselines (Awaiting Measured VM Execution)}",
        r"\label{tab:baseline_comparison}",
        r"\begin{tabular}{lcccc}",
        r"\hline",
        r"\textbf{Method} & \textbf{Macro-F1} & \textbf{Accuracy} & \textbf{Coverage} & \textbf{Non-Abst. Acc} \\",
        r"\hline",
        r"Syscall Only & [Pending Kali] & [Pending] & [Pending] & [Pending] \\",
        r"Block-Layer Only & [Pending Kali] & [Pending] & [Pending] & [Pending] \\",
        r"Scheduler Only & [Pending Kali] & [Pending] & [Pending] & [Pending] \\",
        r"\textbf{Fused Rule Classifier} & [Pending Kali] & [Pending] & [Pending] & [Pending] \\",
        r"\hline",
        r"\end{tabular}",
        r"\end{table}",
    ]
    with open(tables_dir / "baseline_table.tex", "w", encoding="utf-8") as f:
        f.write("\n".join(table_lines) + "\n")

    macros = [
        r"\newcommand{\ValFusedMacroF1}{[Pending Execution]}",
        r"\newcommand{\ValFusedAccuracy}{[Pending Execution]}",
        r"\newcommand{\ValFusedCoverage}{[Pending Execution]}",
        r"\newcommand{\ValOverheadPercent}{[Pending Execution]}",
    ]
    with open(macros_file, "w", encoding="utf-8") as f:
        f.write("\n".join(macros) + "\n")

def main():
    if len(sys.argv) < 2:
        print("Usage: python generate_report_data.py <results_dir> [report_dir]")
        sys.exit(1)
    res_dir = Path(sys.argv[1])
    rep_dir = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("report")
    generate_latex_tables(res_dir, rep_dir)

if __name__ == "__main__":
    main()
