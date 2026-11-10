#!/usr/bin/env python3
"""
Reproducible Experiment Runner for eBPF Application Stall Fingerprinting.

Executes the full experimental matrix across:
- 5 controlled workload conditions (CPU, Read, Write-Sync, Sched-Contention, Sleep)
- 3 concurrency levels (e.g. 1, 2, 4 workers)
- Configurable repetitions (e.g. 3-5 trials)
- Unmonitored baseline vs monitored eBPF tracing (to measure probe overhead)
- Full correlation, feature extraction, rule classification, baseline comparison, and ML evaluation.
"""

import sys
import os
import time
import argparse
import logging
import json
import yaml
from pathlib import Path
from datetime import datetime
import numpy as np
import pandas as pd

# Ensure src and root are in sys.path
SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))

from stall_fingerprint.event_schema import EventReader, EventWriter, DiagnosticEvent, EventType
from stall_fingerprint.collector import BPFCollector, BPFCollectorError
from stall_fingerprint.workload_supervisor import WorkloadSupervisor
from stall_fingerprint.correlation import EventCorrelator
from stall_fingerprint.feature_extraction import extract_features_table
from stall_fingerprint.classifier_rules import RuleBasedClassifier
from stall_fingerprint.baselines import (
    SyscallOnlyClassifier,
    BlockOnlyClassifier,
    SchedulerOnlyClassifier,
)
from stall_fingerprint.classifier_ml import LightweightMLClassifier
from stall_fingerprint.evaluation import (
    compute_classification_metrics, compute_overhead_metrics,
    compute_cpu_usage_metrics, compute_stall_duration_error, compute_confidence_metrics,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("run_experiments")

def load_config(config_path: Path) -> dict:
    if not config_path.exists():
        logger.warning(f"Config {config_path} not found. Using defaults.")
        return {}
    with open(config_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def workload_scenarios(workload_type: str, profile: dict, config: dict):
    """Expand reproducible I/O transfer/cache conditions; non-I/O jobs run once."""
    io_cfg = config.get("workloads", {}).get("io_conditions", {})
    sizes = profile.get("io_file_sizes_mb", io_cfg.get("file_sizes_mb", [profile.get("file_size_mb", 32)]))
    if workload_type == "file_read_sequential":
        cache_states = io_cfg.get("read_cache_states", ["cold", "warm"])
        return [
            (f"{state}_{size}mb", {**profile, "file_size_mb": size, "cold_cache": state == "cold"})
            for size in sizes for state in cache_states
        ]
    if workload_type == "file_write_sync":
        return [(f"sync_{size}mb", {**profile, "file_size_mb": size}) for size in sizes]
    return [("default", profile)]

def run_experiment_matrix(
    profile_name: str,
    output_dir: Path,
    config: dict,
    allow_synthetic: bool = False,
    selected_workloads: list = None,
):
    output_dir.mkdir(parents=True, exist_ok=True)
    profiles_cfg = config.get("workloads", {}).get("profiles", {})
    profile = profiles_cfg.get(profile_name, {
        "concurrency_levels": [1, 2],
        "repetitions": 2,
        "cpu_iterations": 500000,
        "file_size_mb": 8,
        "chunk_size_kb": 64,
        "sync_mode": "fsync",
        "sleep_duration_ms": 100,
        "contention_worker_count": 2,
    })

    workload_types = selected_workloads or config.get("workloads", {}).get("workload_types", [
        "cpu_bound",
        "file_read_sequential",
        "file_write_sync",
        "scheduler_contention",
        "intentional_sleep_control",
    ])
    concurrency_levels = profile.get("concurrency_levels", [1, 2, 4])
    repetitions = profile.get("repetitions", 3)

    logger.info(f"=== Starting Experiment Suite [Profile: {profile_name.upper()}] ===")
    logger.info(f"Workloads: {workload_types}")
    logger.info(f"Concurrency Levels: {concurrency_levels}")
    logger.info(f"Repetitions per condition: {repetitions}")
    logger.info(f"Output Directory: {output_dir}")

    # Save run config
    run_meta = {
        "profile": profile_name,
        "timestamp": datetime.now().isoformat(),
        "workloads": workload_types,
        "concurrency_levels": concurrency_levels,
        "repetitions": repetitions,
        "profile_params": profile,
        "io_conditions": config.get("workloads", {}).get("io_conditions", {}),
        "expanded_scenarios": [],
        "allow_synthetic": allow_synthetic,
    }
    with open(output_dir / "run_config.json", "w", encoding="utf-8") as f:
        json.dump(run_meta, f, indent=2)

    # Check BCC / eBPF environment
    can_use_bpf = False
    try:
        import bcc
        if os.name == "posix" and os.geteuid() == 0:
            can_use_bpf = True
    except ImportError:
        pass

    if not can_use_bpf and not allow_synthetic:
        error_msg = (
            "CRITICAL: eBPF tracing requires Linux kernel with root/CAP_BPF privileges and BCC installed.\n"
            "This environment does not have real eBPF tracing capabilities.\n"
            "By safety policy, the default full experiment command will NEVER silently fall back to simulation.\n"
            "Please run this experiment inside the target Kali Linux VirtualBox VM.\n"
            "(For offline development or unit testing only, pass --allow-synthetic-dev-only)."
        )
        logger.error(error_msg)
        raise RuntimeError(error_msg)

    supervisor = WorkloadSupervisor()
    correlator = EventCorrelator(window_margin_ns=5_000_000)
    raw_events_path = output_dir / "raw_events.jsonl"

    all_op_records = []
    unmonitored_durations_map = {}
    monitored_durations_map = {}
    unmonitored_cpu_map = {}
    monitored_cpu_map = {}
    unmonitored_throughput_map = {}
    monitored_throughput_map = {}

    scenarios = [
        (w, scenario_name, scenario_params)
        for w in workload_types
        for scenario_name, scenario_params in workload_scenarios(w, profile, config)
    ]
    run_meta["expanded_scenarios"] = [f"{w}:{name}" for w, name, _ in scenarios]
    with open(output_dir / "run_config.json", "w", encoding="utf-8") as f:
        json.dump(run_meta, f, indent=2)

    # 1. Measure Unmonitored Baselines (Performance Control)
    logger.info("--- Phase 1: Measuring Unmonitored Baseline Workloads (Control) ---")
    for w_type, scenario_name, scenario_params in scenarios:
        for conc in concurrency_levels:
            for rep in range(repetitions):
                trial_id = f"unmon_{w_type}_{scenario_name}_c{conc}_r{rep}"
                try:
                    recs = supervisor.execute_workload_trial(
                        workload_type=w_type,
                        trial_id=trial_id,
                        concurrency=conc,
                        params=scenario_params,
                        register_pid_fn=None,
                    )
                    for r in recs:
                        key = f"{w_type}|{scenario_name}|c{conc}"
                        unmonitored_durations_map.setdefault(key, []).append(r.duration_ns / 1_000_000)
                        unmonitored_cpu_map.setdefault(key, []).append(
                            int(r.parameters.get("process_cpu_ns", 0)) / 1_000_000
                        )
                        byte_count = int(r.parameters.get("total_bytes_read", r.parameters.get("bytes_written", 0)) or 0)
                        if byte_count:
                            unmonitored_throughput_map.setdefault(key, []).append(
                                (byte_count / (1024 * 1024)) / (r.duration_ns / 1_000_000_000)
                            )
                except Exception as e:
                    logger.warning(f"Unmonitored run failed for {w_type}: {e}")

    # 2. Measure Monitored Workloads with eBPF Tracing
    logger.info("--- Phase 2: Executing Monitored Tracing Workloads ---")
    total_dropped_events = 0

    with EventWriter(raw_events_path) as event_writer:
        for w_type, scenario_name, scenario_params in scenarios:
            for conc in concurrency_levels:
                for rep in range(repetitions):
                    trial_id = f"trial_{w_type}_{scenario_name}_c{conc}_r{rep}"
                    logger.info(f"Running trial: {trial_id}")

                    collector = None
                    if can_use_bpf:
                        try:
                            collector = BPFCollector(
                                output_path=raw_events_path,
                                perf_page_cnt=config.get("collector", {}).get("perf_buffer_page_cnt", 64),
                            )
                            collector.start()
                        except Exception as e:
                            logger.error(f"BPF Collector failed to start: {e}")
                            if not allow_synthetic:
                                raise RuntimeError(
                                    f"CRITICAL: Failed to initialize eBPF collector for {trial_id}: {e}. "
                                    "Failing closed to prevent uninstrumented runs masquerading as monitored data."
                                )
                            collector = None

                    # Execute workload with target PID registration coordination
                    reg_fn = collector.add_target_pid if collector is not None else None
                    try:
                        recs = supervisor.execute_workload_trial(
                            workload_type=w_type,
                            trial_id=trial_id,
                            concurrency=conc,
                            params=scenario_params,
                            register_pid_fn=reg_fn,
                        )
                        # Record inner workload duration for honest, like-for-like comparison
                        for r in recs:
                            key = f"{w_type}|{scenario_name}|c{conc}"
                            monitored_durations_map.setdefault(key, []).append(r.duration_ns / 1_000_000)
                            monitored_cpu_map.setdefault(key, []).append(
                                int(r.parameters.get("process_cpu_ns", 0)) / 1_000_000
                            )
                            byte_count = int(r.parameters.get("total_bytes_read", r.parameters.get("bytes_written", 0)) or 0)
                            if byte_count:
                                monitored_throughput_map.setdefault(key, []).append(
                                    (byte_count / (1024 * 1024)) / (r.duration_ns / 1_000_000_000)
                                )
                        all_op_records.extend(recs)
                    except Exception as e:
                        logger.error(f"Workload {trial_id} failed: {e}")
                        if not allow_synthetic:
                            raise
                    finally:
                        if collector is not None:
                            total_dropped_events += collector.total_events_lost
                            collector.stop()

    # Save workload operations metadata table
    workload_df = pd.DataFrame([r.to_dict() for r in all_op_records])
    workload_df.to_csv(output_dir / "workload_runs.csv", index=False)
    logger.info(f"Workload records saved: {len(workload_df)} operations.")

    # 3. Read Raw Events & Perform Correlation
    logger.info("--- Phase 3: Correlating Telemetry Events to Workload Windows ---")
    event_reader = EventReader(raw_events_path)
    all_events = event_reader.read_all()
    logger.info(f"Total raw events loaded: {len(all_events)}")

    # Incorporate any dropped event records from event stream
    for ev in all_events:
        if ev.event_type == EventType.DROPPED_EVENT_STATS.value:
            total_dropped_events = max(total_dropped_events, getattr(ev, "total_events_lost", 0))

    correlated_windows = correlator.correlate_all(all_op_records, all_events)

    # 4. Extract Feature Table
    logger.info("--- Phase 4: Extracting Quantitative Features ---")
    features_df = extract_features_table(correlated_windows)
    features_df.to_csv(output_dir / "features.csv", index=False)
    logger.info(f"Features extracted: shape {features_df.shape}")

    # 5. Rule-Based Classification
    logger.info("--- Phase 5: Executing Rule-Based Classification ---")
    rule_classifier = RuleBasedClassifier(config.get("classifier_rules", {}))
    preds, exps = rule_classifier.predict_dataframe(features_df)
    features_df["predicted_rule_fused"] = preds
    features_df["rule_explanation"] = exps
    rule_confidences = [rule_classifier.predict_sample(row.to_dict()).confidence for _, row in features_df.iterrows()]
    features_df["rule_confidence"] = rule_confidences

    # 6. Evaluate Single-Source Baselines
    logger.info("--- Phase 6: Evaluating Single-Source Baselines ---")
    base_syscall = SyscallOnlyClassifier()
    base_block = BlockOnlyClassifier()
    base_sched = SchedulerOnlyClassifier()

    features_df["pred_baseline_syscall"] = base_syscall.predict_dataframe(features_df)
    features_df["pred_baseline_block"] = base_block.predict_dataframe(features_df)
    features_df["pred_baseline_sched"] = base_sched.predict_dataframe(features_df)

    # 7. Evaluate Lightweight ML Classifier (Strictly on Held-Out Test Split)
    logger.info("--- Phase 7: Training & Evaluating Lightweight ML Classifier on Held-Out Test Split ---")
    ml_classifier = LightweightMLClassifier(max_depth=3, random_state=42)
    ml_fitted = False
    ml_test_metrics = None
    ml_train_diagnostics = None

    if not features_df.empty:
        train_df, test_df = ml_classifier.split_data_by_trial(features_df, test_size=0.30, group_col="parent_trial_id")
        ml_fitted = ml_classifier.fit(train_df, target_col="expected_label")
        if ml_fitted:
            # Predict for full table for record-keeping
            features_df["pred_ml_tree"] = ml_classifier.predict(features_df)

            # Calculate primary headline ML metrics STRICTLY on held-out test split
            test_preds = ml_classifier.predict(test_df)
            test_df["pred_ml_tree"] = test_preds
            test_df.to_csv(output_dir / "test_predictions.csv", index=False)
            ml_test_metrics = compute_classification_metrics(test_df["expected_label"].tolist(), test_preds)

            # Training diagnostics
            train_preds = ml_classifier.predict(train_df)
            ml_train_diagnostics = compute_classification_metrics(train_df["expected_label"].tolist(), train_preds)
            logger.info(f"ML Held-Out Test Macro-F1: {ml_test_metrics['macro_f1']:.3f} (Train Diagnostic F1: {ml_train_diagnostics['macro_f1']:.3f})")
        else:
            features_df["pred_ml_tree"] = "indeterminate"
    else:
        features_df["pred_ml_tree"] = "indeterminate"

    # Save predictions
    features_df.to_csv(output_dir / "predictions.csv", index=False)

    # 8. Compute Metrics & Baseline Comparison
    logger.info("--- Phase 8: Generating Evaluation Metrics & Baseline Table ---")
    y_true = features_df["expected_label"].tolist() if not features_df.empty else []

    methods = {
        "baseline_syscall_only": features_df["pred_baseline_syscall"].tolist() if not features_df.empty else [],
        "baseline_block_only": features_df["pred_baseline_block"].tolist() if not features_df.empty else [],
        "baseline_sched_only": features_df["pred_baseline_sched"].tolist() if not features_df.empty else [],
        "fused_rule_classifier": features_df["predicted_rule_fused"].tolist() if not features_df.empty else [],
    }

    all_metrics = {}
    comparison_rows = []

    for name, y_pred in methods.items():
        m = compute_classification_metrics(y_true, y_pred)
        all_metrics[name] = m
        comparison_rows.append({
            "method": name,
            "overall_accuracy": m["overall_accuracy"],
            "macro_f1": m["macro_f1"],
            "abstention_rate": m["abstention_rate"],
            "coverage": m["coverage"],
            "non_abstained_accuracy": m["non_abstained_accuracy"],
            "io_wait_f1": m["per_class"].get("io_wait_dominated", {}).get("f1", 0.0),
            "sched_wait_f1": m["per_class"].get("scheduler_wait_dominated", {}).get("f1", 0.0),
            "cpu_f1": m["per_class"].get("cpu_syscall_dominated", {}).get("f1", 0.0),
            "indeterminate_f1": m["per_class"].get("indeterminate", {}).get("f1", 0.0),
        })

    all_metrics["fused_confidence"] = compute_confidence_metrics(y_true, preds, rule_confidences)
    all_metrics["stall_duration_estimation"] = compute_stall_duration_error(features_df)
    if not features_df.empty:
        io_features_df = features_df[features_df["workload_type"].isin(["file_read_sequential", "file_write_sync"])]
        throughput_summary = (
            io_features_df.groupby(["workload_type", "file_size_mb", "cache_state", "concurrency"], dropna=False)
            .agg(samples=("trial_id", "count"), monitored_mean_mib_s=("throughput_mib_s", "mean"),
                 monitored_p50_mib_s=("throughput_mib_s", "median"), monitored_p99_latency_ms=("wall_duration_ms", lambda x: x.quantile(0.99)))
            .reset_index()
        )
        control_rates = []
        for _, row in throughput_summary.iterrows():
            workload = row["workload_type"]
            size = int(row["file_size_mb"])
            cache = row["cache_state"]
            concurrency = int(row["concurrency"])
            scenario = f"{cache}_{size}mb" if workload == "file_read_sequential" else f"sync_{size}mb"
            all_rates = [
                rate for key, rates in unmonitored_throughput_map.items()
                if key == f"{workload}|{scenario}|c{concurrency}" for rate in rates
            ]
            condition_key = f"{workload}|{scenario}|c{concurrency}"
            control_durations = unmonitored_durations_map.get(condition_key, [])
            baseline_rate = float(np.mean(all_rates)) if all_rates else float("nan")
            monitored_rate = float(row["monitored_mean_mib_s"])
            delta = ((monitored_rate - baseline_rate) / baseline_rate * 100.0) if baseline_rate > 0 else float("nan")
            baseline_p99 = float(np.percentile(control_durations, 99)) if control_durations else float("nan")
            monitor_p99 = float(row["monitored_p99_latency_ms"])
            p99_delta = monitor_p99 - baseline_p99 if np.isfinite(baseline_p99) else float("nan")
            control_rates.append((baseline_rate, delta, baseline_p99, p99_delta))
        throughput_summary["unmonitored_mean_mib_s"] = [x[0] for x in control_rates]
        throughput_summary["throughput_change_percent"] = [x[1] for x in control_rates]
        throughput_summary["unmonitored_p99_latency_ms"] = [x[2] for x in control_rates]
        throughput_summary["p99_latency_change_ms"] = [x[3] for x in control_rates]
        # Keep the report generator's established column name for monitored throughput.
        throughput_summary["mean_mib_s"] = throughput_summary["monitored_mean_mib_s"]
        throughput_summary["p99_latency_ms"] = throughput_summary["monitored_p99_latency_ms"]
        throughput_summary.to_csv(output_dir / "throughput_summary.csv", index=False)

    # Size-transfer evaluation: hold out each I/O file size, train on all other
    # operations (including other classes), and evaluate only I/O at the held-out size.
    transfer_rows = []
    io_rows = features_df[features_df["workload_type"].isin(["file_read_sequential", "file_write_sync"])].dropna(subset=["file_size_mb"])
    for held_out_size in sorted(io_rows["file_size_mb"].unique()):
        test_mask = io_rows["file_size_mb"] == held_out_size
        test_df = io_rows[test_mask].copy()
        train_df = features_df[features_df["file_size_mb"].isna() | (features_df["file_size_mb"] != held_out_size)].copy()
        transfer_model = LightweightMLClassifier(max_depth=3, random_state=42)
        fitted = transfer_model.fit(train_df, target_col="expected_label")
        if fitted and not test_df.empty:
            transfer_metrics = compute_classification_metrics(test_df["expected_label"].tolist(), transfer_model.predict(test_df))
            transfer_rows.append({"held_out_file_size_mb": held_out_size, "status": "evaluated", **{
                k: transfer_metrics[k] for k in ("total_samples", "macro_f1", "overall_accuracy", "coverage", "abstention_rate")
            }})
        else:
            transfer_rows.append({"held_out_file_size_mb": held_out_size, "status": "insufficient_training_data", "total_samples": len(test_df)})
    pd.DataFrame(transfer_rows).to_csv(output_dir / "transfer_evaluation.csv", index=False)

    # Add Decision Tree metrics evaluated strictly on held-out test data
    if ml_fitted and ml_test_metrics:
        all_metrics["ml_decision_tree"] = ml_test_metrics
        all_metrics["ml_train_diagnostics"] = ml_train_diagnostics
        comparison_rows.append({
            "method": "ml_decision_tree",
            "overall_accuracy": ml_test_metrics["overall_accuracy"],
            "macro_f1": ml_test_metrics["macro_f1"],
            "abstention_rate": ml_test_metrics["abstention_rate"],
            "coverage": ml_test_metrics["coverage"],
            "non_abstained_accuracy": ml_test_metrics["non_abstained_accuracy"],
            "io_wait_f1": ml_test_metrics["per_class"].get("io_wait_dominated", {}).get("f1", 0.0),
            "sched_wait_f1": ml_test_metrics["per_class"].get("scheduler_wait_dominated", {}).get("f1", 0.0),
            "cpu_f1": ml_test_metrics["per_class"].get("cpu_syscall_dominated", {}).get("f1", 0.0),
            "indeterminate_f1": ml_test_metrics["per_class"].get("indeterminate", {}).get("f1", 0.0),
        })

    comparison_df = pd.DataFrame(comparison_rows)
    comparison_df.to_csv(output_dir / "baseline_comparison.csv", index=False)

    # Overhead metrics: like-for-like comparison of internal workload durations
    flat_unmon = [v for sub in unmonitored_durations_map.values() for v in sub]
    flat_mon = [v for sub in monitored_durations_map.values() for v in sub]
    overhead_res = compute_overhead_metrics(flat_unmon, flat_mon, total_events=len(all_events), dropped_events=total_dropped_events)
    all_metrics["instrumentation_overhead"] = overhead_res
    max_overhead = config.get("evaluation", {}).get("max_overhead_percent", 10.0)
    all_metrics["predeclared_overhead_budget"] = {
        "maximum_percent": max_overhead,
        "measured_percent": overhead_res["overhead_percent"],
        "within_budget": overhead_res["overhead_percent"] <= max_overhead,
    }
    unmon_cpu_pairs = [
        (cpu, wall)
        for key in sorted(set(unmonitored_cpu_map) & set(unmonitored_durations_map))
        for cpu, wall in zip(unmonitored_cpu_map[key], unmonitored_durations_map[key])
    ]
    mon_cpu_pairs = [
        (cpu, wall)
        for key in sorted(set(monitored_cpu_map) & set(monitored_durations_map))
        for cpu, wall in zip(monitored_cpu_map[key], monitored_durations_map[key])
    ]
    all_metrics["unmonitored_process_cpu"] = compute_cpu_usage_metrics(
        [p[0] for p in unmon_cpu_pairs], [p[1] for p in unmon_cpu_pairs]
    )
    all_metrics["monitored_process_cpu"] = compute_cpu_usage_metrics(
        [p[0] for p in mon_cpu_pairs], [p[1] for p in mon_cpu_pairs]
    )
    cpu_un_pct = all_metrics["unmonitored_process_cpu"]["mean_cpu_percent_of_one_core"]
    cpu_mon_pct = all_metrics["monitored_process_cpu"]["mean_cpu_percent_of_one_core"]
    all_metrics["process_cpu_overhead"] = {
        "delta_percentage_points": round(cpu_mon_pct - cpu_un_pct, 2),
        "relative_percent": round((cpu_mon_pct - cpu_un_pct) / cpu_un_pct * 100.0, 2) if cpu_un_pct > 0 else None,
    }

    # Per-workload overhead breakdown
    per_workload_overhead = {}
    for key in sorted(set(unmonitored_durations_map) & set(monitored_durations_map)):
        u_sub = unmonitored_durations_map.get(key, [])
        m_sub = monitored_durations_map.get(key, [])
        if u_sub and m_sub:
            per_workload_overhead[key] = compute_overhead_metrics(u_sub, m_sub, total_events=0, dropped_events=0)
    all_metrics["per_workload_overhead"] = per_workload_overhead

    single_layer_f1 = [
        all_metrics.get(k, {}).get("macro_f1", 0.0)
        for k in ("baseline_syscall_only", "baseline_block_only", "baseline_sched_only")
    ]
    all_metrics["success_criteria"] = {
        "h1_fusion_beats_best_single_layer": all_metrics.get("fused_rule_classifier", {}).get("macro_f1", 0.0) > max(single_layer_f1, default=0.0),
        "overhead_budget_met": all_metrics["predeclared_overhead_budget"]["within_budget"],
        "overhead_budget_percent": max_overhead,
        "h2_reported_as_diagnostics": "fused_confidence and abstention metrics; inspect examples before claiming abstention prevented errors",
    }

    with open(output_dir / "metrics.json", "w", encoding="utf-8") as f:
        json.dump(all_metrics, f, indent=2)

    logger.info("=== Experiment Run Finished Successfully ===")
    logger.info(f"Baseline Comparison Summary:\n{comparison_df.to_string(index=False)}")
    logger.info(f"Overhead Summary: {overhead_res['overhead_percent']}% wall-clock delta")

    return output_dir

def main():
    parser = argparse.ArgumentParser(description="eBPF Application Stall Fingerprinting Experiment Runner")
    parser.add_argument("--profile", choices=["quick", "full"], default="quick", help="Experiment profile")
    parser.add_argument("--config", default="config/experiment_config.yaml", help="Path to config file")
    parser.add_argument("--output-dir", default=None, help="Output directory path")
    parser.add_argument("--allow-synthetic-dev-only", action="store_true", help="Permit synthetic fixtures strictly for offline host development/testing")
    parser.add_argument("--workloads", nargs="+", default=None, help="Specific workloads to execute")
    args = parser.parse_args()

    cfg_path = Path(args.config)
    if not cfg_path.is_absolute():
        cfg_path = REPO_ROOT / cfg_path
    config = load_config(cfg_path)

    if args.output_dir:
        out_dir = Path(args.output_dir)
    else:
        timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_dir = REPO_ROOT / "results" / f"run_{timestamp_str}_{args.profile}"

    run_experiment_matrix(
        profile_name=args.profile,
        output_dir=out_dir,
        config=config,
        allow_synthetic=args.allow_synthetic_dev_only,
        selected_workloads=args.workloads,
    )

if __name__ == "__main__":
    main()
