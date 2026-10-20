"""
Feature Extraction Pipeline for Stall Fingerprinting.

Extracts structured quantitative features from window-correlated events,
ensuring non-overlapping interval union for durations and bounded ratios in [0.0, 1.0].
"""

import pandas as pd
from typing import List, Dict, Any, Optional
from stall_fingerprint.correlation import WindowCorrelatedEvents, compute_interval_union

def extract_features_from_correlated_window(cw: WindowCorrelatedEvents) -> Dict[str, Any]:
    op = cw.operation
    wall_duration_ns = max(op.duration_ns, 1)  # Guard against zero-division

    # --- 1. Syscall Layer Features ---
    syscall_intervals = []
    raw_syscall_durations = []
    fsync_count = 0
    read_count = 0
    write_count = 0

    for s in cw.syscall_events:
        d = max(s.duration_ns, 0)
        raw_syscall_durations.append(d)
        end_ts = s.timestamp_ns
        start_ts = end_ts - d
        syscall_intervals.append((start_ts, end_ts))

        name = s.syscall_name.lower()
        if "fsync" in name or "fdatasync" in name:
            fsync_count += 1
        elif "read" in name:
            read_count += 1
        elif "write" in name:
            write_count += 1

    syscall_count = len(cw.syscall_events)
    raw_syscall_sum_ns = sum(raw_syscall_durations)
    max_syscall_duration_ns = max(raw_syscall_durations) if raw_syscall_durations else 0

    # Non-overlapping union clipped to operation window [op.start_ns, op.end_ns]
    non_overlap_syscall_ns = compute_interval_union(
        syscall_intervals,
        clip_min=op.start_ns,
        clip_max=op.end_ns,
    )
    syscall_duration_ratio = min(max(non_overlap_syscall_ns / wall_duration_ns, 0.0), 1.0)

    # --- 2. Block Layer Features ---
    block_issues = [b for b in cw.block_events if "ISSUE" in b.event_type]
    block_completes = [b for b in cw.block_events if "COMPLETE" in b.event_type]
    total_block_bytes = sum(b.bytes_count for b in cw.block_events)
    block_errors = sum(1 for b in block_completes if b.error != 0)

    block_issue_count = len(block_issues)
    block_complete_count = len(block_completes)
    has_block_activity = 1 if (block_issue_count > 0 or block_complete_count > 0 or total_block_bytes > 0) else 0

    # --- 3. Scheduler Layer Features ---
    runnable_wait_ns = 0
    sched_switch_count = 0
    sched_wakeup_count = 0
    preemption_count = 0

    for sc in cw.sched_events:
        if "WAKEUP" in sc.event_type:
            sched_wakeup_count += 1
        elif "SWITCH" in sc.event_type:
            sched_switch_count += 1
            if sc.is_on_cpu:
                runnable_wait_ns += max(sc.runnable_delay_ns, 0)
            elif sc.prev_state == 0:
                preemption_count += 1

    # Clip runnable wait to wall duration
    clipped_runnable_wait_ns = min(runnable_wait_ns, wall_duration_ns)
    sched_wait_ratio = min(max(clipped_runnable_wait_ns / wall_duration_ns, 0.0), 1.0)

    # --- 4. Observed On-CPU and Unobserved / Gap Account ---
    # Observed on-CPU is estimated by excluding known blocking syscalls and runnable delay
    accounted_delay_ns = min(non_overlap_syscall_ns + clipped_runnable_wait_ns, wall_duration_ns)
    observed_on_cpu_ns = wall_duration_ns - accounted_delay_ns
    on_cpu_ratio = min(max(observed_on_cpu_ns / wall_duration_ns, 0.0), 1.0)

    # If neither CPU nor known I/O nor runnable wait is substantiated (e.g. sleep control without syscall/sched events)
    is_empty_window = 1 if (syscall_count == 0 and has_block_activity == 0 and sched_switch_count == 0) else 0

    unobserved_ns = 0
    if is_empty_window:
        unobserved_ns = wall_duration_ns
        on_cpu_ratio = 0.0
    unobserved_ratio = min(max(unobserved_ns / wall_duration_ns, 0.0), 1.0)

    return {
        "trial_id": op.trial_id,
        "workload_type": op.workload_type,
        "operation_id": op.operation_id,
        "pid": op.pid,
        "tid": op.tid,
        "concurrency": op.concurrency,
        "intervention_label": op.intervention_label,
        "expected_label": op.expected_label,
        "start_ns": op.start_ns,
        "end_ns": op.end_ns,
        "wall_duration_ns": wall_duration_ns,
        "wall_duration_ms": round(wall_duration_ns / 1_000_000, 3),

        # Syscall features
        "syscall_count": syscall_count,
        "raw_syscall_sum_ns": raw_syscall_sum_ns,
        "non_overlap_syscall_ns": non_overlap_syscall_ns,
        "max_syscall_duration_ns": max_syscall_duration_ns,
        "syscall_duration_ratio": round(syscall_duration_ratio, 4),
        "fsync_count": fsync_count,
        "read_count": read_count,
        "write_count": write_count,

        # Block layer features
        "block_issue_count": block_issue_count,
        "block_complete_count": block_complete_count,
        "block_total_bytes": total_block_bytes,
        "has_block_activity": has_block_activity,
        "block_errors": block_errors,

        # Sched features
        "sched_switch_count": sched_switch_count,
        "sched_wakeup_count": sched_wakeup_count,
        "preemption_count": preemption_count,
        "runnable_wait_ns": clipped_runnable_wait_ns,
        "sched_wait_ratio": round(sched_wait_ratio, 4),

        # Accounting & Data Quality
        "observed_on_cpu_ns": observed_on_cpu_ns,
        "on_cpu_ratio": round(on_cpu_ratio, 4),
        "unobserved_ns": unobserved_ns,
        "unobserved_ratio": round(unobserved_ratio, 4),
        "is_empty_window": is_empty_window,
        "dropped_event_count": cw.dropped_events_count,
    }

def extract_features_table(correlated_windows: List[WindowCorrelatedEvents]) -> pd.DataFrame:
    """Extracts features for all correlated windows into a pandas DataFrame."""
    records = [extract_features_from_correlated_window(cw) for cw in correlated_windows]
    if not records:
        return pd.DataFrame()
    return pd.DataFrame(records)
