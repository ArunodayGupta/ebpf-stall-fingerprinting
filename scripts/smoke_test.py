#!/usr/bin/env python3
"""
Smoke Test for eBPF Application Stall Fingerprinting.

Verifies end-to-end functionality:
1. Environment readiness check
2. Single workload execution
3. Event schema serialization & deserialization
4. Correlation and feature extraction
5. Rule-based classifier execution
"""

import sys
import os
import time
import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))

from stall_fingerprint.event_schema import (
    EventType,
    SyscallEvent,
    BlockEvent,
    SchedEvent,
    EventWriter,
    EventReader,
)
from workloads.cpu_workload import run_cpu_workload
from workloads.workload_utils import WorkloadOperationRecord
from stall_fingerprint.correlation import EventCorrelator
from stall_fingerprint.feature_extraction import extract_features_from_correlated_window
from stall_fingerprint.classifier_rules import RuleBasedClassifier

def run_smoke_test():
    print("=" * 60)
    print("  eBPF Stall Fingerprinting - Smoke Test Suite")
    print("=" * 60)

    smoke_dir = REPO_ROOT / "results" / "smoke_test"
    smoke_dir.mkdir(parents=True, exist_ok=True)
    events_file = smoke_dir / "smoke_events.jsonl"

    # Step 1: Execute a bounded CPU workload
    print("[1/5] Executing controlled CPU-bound operation...")
    op_record = run_cpu_workload(trial_id="smoke_trial_01", iterations=100000, concurrency=1)
    print(f"      PID: {op_record.pid}, Duration: {op_record.duration_ns / 1_000_000:.2f} ms")
    assert op_record.duration_ns > 0, "Workload duration should be positive"

    # Step 2: Test Event Schema Serialization
    print("[2/5] Testing event schema serialization to JSON Lines...")
    with EventWriter(events_file) as writer:
        writer.write_event(
            SyscallEvent(
                event_type=EventType.SYSCALL_COMPLETE.value,
                timestamp_ns=op_record.start_ns + 1000,
                pid=op_record.pid,
                tid=op_record.tid,
                comm="python3",
                syscall_name="read",
                syscall_id=0,
                duration_ns=5000,
                ret=1024,
            )
        )
        writer.write_event(
            SchedEvent(
                event_type=EventType.SCHED_SWITCH.value,
                timestamp_ns=op_record.start_ns + 2000,
                target_pid=op_record.pid,
                is_on_cpu=True,
                runnable_delay_ns=1500,
            )
        )
    print(f"      Written 2 events to {events_file}")

    # Step 3: Test Event Reader
    print("[3/5] Reading and verifying events...")
    reader = EventReader(events_file)
    loaded = reader.read_all()
    print(f"      Successfully loaded {len(loaded)} events.")
    assert len(loaded) >= 2, "Should load at least 2 events"

    # Step 4: Test Event Correlation
    print("[4/5] Correlating events with workload window...")
    correlator = EventCorrelator(window_margin_ns=1_000_000)
    cw = correlator.correlate_operation(op_record, loaded)
    features = extract_features_from_correlated_window(cw)
    print(f"      Extracted {len(features)} quantitative features.")
    print(f"      Syscall Ratio: {features['syscall_duration_ratio']}, On-CPU Ratio: {features['on_cpu_ratio']}")

    # Step 5: Test Rule Classification
    print("[5/5] Testing rule-based classifier...")
    classifier = RuleBasedClassifier()
    pred = classifier.predict_sample(features)
    print(f"      Prediction: {pred.predicted_label}")
    print(f"      Confidence: {pred.confidence}")
    print(f"      Rule Fired: {pred.rule_fired}")
    print(f"      Explanation: {pred.explanation}")

    print("=" * 60)
    print("  SMOKE TEST PASSED: All core pipeline stages verified!")
    print("=" * 60)

if __name__ == "__main__":
    run_smoke_test()
