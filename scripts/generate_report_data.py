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
    throughput_file = results_dir / "throughput_summary.csv"
    transfer_file = results_dir / "transfer_evaluation.csv"

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

    cpu_un = metrics.get("unmonitored_process_cpu", {})
    cpu_mon = metrics.get("monitored_process_cpu", {})
    stall_est = metrics.get("stall_duration_estimation", {})
    budget = metrics.get("predeclared_overhead_budget", {})
    extra_lines = [
        r"\begin{table}[t]", r"\centering", r"\caption{CPU Use and Declared Overhead Budget}",
        r"\label{tab:cpu_budget}", r"\begin{tabular}{lc}", r"\hline",
        r"\textbf{Metric} & \textbf{Measured} \\", r"\hline",
        f"Unmonitored process CPU (\\% of one core) & {cpu_un.get('mean_cpu_percent_of_one_core', 0):.2f} \\\\",
        f"Monitored process CPU (\\% of one core) & {cpu_mon.get('mean_cpu_percent_of_one_core', 0):.2f} \\\\",
        f"CPU use change (percentage points) & {metrics.get('process_cpu_overhead', {}).get('delta_percentage_points', 0):.2f} \\\\",
        f"Overhead budget & {budget.get('maximum_percent', 0):.1f}\\% ({'PASS' if budget.get('within_budget') else 'EXCEEDS'}) \\\\",
        f"Injected sleep duration MAE & {stall_est.get('mae_ms') if stall_est.get('mae_ms') is not None else 'N/A'} ms \\\\",
        r"\hline", r"\end{tabular}", r"\end{table}",
    ]
    with open(tables_dir / "cpu_and_budget_table.tex", "w", encoding="utf-8") as f:
        f.write("\n".join(extra_lines) + "\n")

    if throughput_file.exists():
        throughput = pd.read_csv(throughput_file)
        lines = [r"\begin{table}[t]", r"\centering", r"\caption{Measured I/O Throughput by Workload Condition}",
                 r"\label{tab:throughput}", r"\begin{tabular}{lrrr}", r"\hline",
                 r"\textbf{Condition} & \textbf{N} & \textbf{Mean MiB/s} & \textbf{p99 ms} \\", r"\hline"]
        for _, row in throughput.iterrows():
            if row.get("workload_type") not in ("file_read_sequential", "file_write_sync"):
                continue
            cond = f"{row['workload_type']} {row.get('cache_state', '')} {row.get('file_size_mb', '')}MB"
            lines.append(f"{cond} & {int(row['samples'])} & {row['mean_mib_s']:.2f} & {row['p99_latency_ms']:.2f} \\\\")
        lines.extend([r"\hline", r"\end{tabular}", r"\end{table}"])
        with open(tables_dir / "throughput_table.tex", "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")

    if transfer_file.exists():
        transfer = pd.read_csv(transfer_file)
        lines = [r"\begin{table}[t]", r"\centering", r"\caption{Decision Tree Transfer to Held-Out I/O File Sizes}",
                 r"\label{tab:transfer}", r"\begin{tabular}{lrrl}", r"\hline",
                 r"\textbf{Held-Out Size} & \textbf{N} & \textbf{Macro-F1} & \textbf{Status} \\", r"\hline"]
        for _, row in transfer.iterrows():
            f1 = f"{row['macro_f1']:.3f}" if pd.notna(row.get("macro_f1")) else "N/A"
            lines.append(f"{row['held_out_file_size_mb']} MB & {int(row['total_samples'])} & {f1} & {row['status']} \\\\")
        lines.extend([r"\hline", r"\end{tabular}", r"\end{table}"])
        with open(tables_dir / "transfer_table.tex", "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")

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

    ov_lines = [
        r"\begin{table}[t]",
        r"\centering",
        r"\caption{eBPF Instrumentation Overhead Profile (Awaiting Measured VM Execution)}",
        r"\label{tab:overhead_profile}",
        r"\begin{tabular}{lcc}",
        r"\hline",
        r"\textbf{Metric} & \textbf{Unmonitored} & \textbf{Monitored (eBPF)} \\",
        r"\hline",
        r"Mean Duration (ms) & [Pending Kali] & [Pending Kali] \\",
        r"Overhead Delta & --- & [Pending Kali] \\",
        r"p50 Tail Latency & --- & [Pending Kali] \\",
        r"p99 Tail Latency & --- & [Pending Kali] \\",
        r"Dropped Event Rate & --- & [Pending Kali] \\",
        r"\hline",
        r"\end{tabular}",
        r"\end{table}",
    ]
    with open(tables_dir / "overhead_table.tex", "w", encoding="utf-8") as f:
        f.write("\n".join(ov_lines) + "\n")

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
