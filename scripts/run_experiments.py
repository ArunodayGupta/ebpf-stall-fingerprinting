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
from stall_fingerprint.evaluation import compute_classification_metrics, compute_overhead_metrics

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("run_experiments")

def load_config(config_path: Path) -> dict:
    if not config_path.exists():
        logger.warning(f"Config {config_path} not found. Using defaults.")
        return {}
    with open(config_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

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
    unmonitored_durations_map = {w: [] for w in workload_types}
    monitored_durations_map = {w: [] for w in workload_types}

    # 1. Measure Unmonitored Baselines (Performance Control)
    logger.info("--- Phase 1: Measuring Unmonitored Baseline Workloads (Control) ---")
    for w_type in workload_types:
        for rep in range(min(repetitions, 3)):
            trial_id = f"unmon_{w_type}_c1_r{rep}"
            try:
                recs = supervisor.execute_workload_trial(
                    workload_type=w_type,
                    trial_id=trial_id,
                    concurrency=1,
                    params=profile,
                )
                for r in recs:
                    unmonitored_durations_map[w_type].append(r.duration_ns / 1_000_000)
            except Exception as e:
                logger.warning(f"Unmonitored run failed for {w_type}: {e}")

    # 2. Measure Monitored Workloads with eBPF Tracing
    logger.info("--- Phase 2: Executing Monitored Tracing Workloads ---")
    with EventWriter(raw_events_path) as event_writer:
        for w_type in workload_types:
            for conc in concurrency_levels:
                for rep in range(repetitions):
                    trial_id = f"trial_{w_type}_c{conc}_r{rep}"
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
                            collector = None

                    # Execute workload
                    t0 = time.monotonic_ns()
                    try:
                        recs = supervisor.execute_workload_trial(
                            workload_type=w_type,
                            trial_id=trial_id,
                            concurrency=conc,
                            params=profile,
                        )
                        t1 = time.monotonic_ns()
                        wall_ms = (t1 - t0) / 1_000_000
                        monitored_durations_map[w_type].append(wall_ms)
                        all_op_records.extend(recs)
                    except Exception as e:
                        logger.error(f"Workload {trial_id} failed: {e}")
                    finally:
                        if collector is not None:
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

    # 6. Evaluate Single-Source Baselines
    logger.info("--- Phase 6: Evaluating Single-Source Baselines ---")
    base_syscall = SyscallOnlyClassifier()
    base_block = BlockOnlyClassifier()
    base_sched = SchedulerOnlyClassifier()

    features_df["pred_baseline_syscall"] = base_syscall.predict_dataframe(features_df)
    features_df["pred_baseline_block"] = base_block.predict_dataframe(features_df)
    features_df["pred_baseline_sched"] = base_sched.predict_dataframe(features_df)

    # 7. Evaluate Lightweight ML Classifier
    logger.info("--- Phase 7: Training & Evaluating Lightweight ML Classifier ---")
    ml_classifier = LightweightMLClassifier(max_depth=3, random_state=42)
    ml_fitted = False
    if not features_df.empty:
        train_df, test_df = ml_classifier.split_data_by_trial(features_df, test_size=0.30)
        ml_fitted = ml_classifier.fit(train_df, target_col="expected_label")
        if ml_fitted:
            features_df["pred_ml_tree"] = ml_classifier.predict(features_df)
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
    if ml_fitted:
        methods["ml_decision_tree"] = features_df["pred_ml_tree"].tolist()

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

    comparison_df = pd.DataFrame(comparison_rows)
    comparison_df.to_csv(output_dir / "baseline_comparison.csv", index=False)

    # Overhead metrics
    flat_unmon = [v for sub in unmonitored_durations_map.values() for v in sub]
    flat_mon = [v for sub in monitored_durations_map.values() for v in sub]
    overhead_res = compute_overhead_metrics(flat_unmon, flat_mon, total_events=len(all_events), dropped_events=0)
    all_metrics["instrumentation_overhead"] = overhead_res

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
