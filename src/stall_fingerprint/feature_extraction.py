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
    parent_trial_id = getattr(op, "parent_trial_id", op.trial_id)
    if not parent_trial_id:
        parent_trial_id = op.trial_id.split("_worker_")[0] if "_worker_" in op.trial_id else op.trial_id

    # --- 1. Syscall Layer Features ---
    storage_syscall_intervals = []
    sleep_syscall_intervals = []
    raw_storage_durations = []
    raw_sleep_durations = []
    fsync_count = 0
    read_count = 0
    write_count = 0
    sleep_syscall_count = 0

    for s in cw.syscall_events:
        d = max(s.duration_ns, 0)
        end_ts = s.timestamp_ns
        start_ts = end_ts - d
        name = s.syscall_name.lower()

        if "nanosleep" in name or "clock_nanosleep" in name:
            sleep_syscall_count += 1
            raw_sleep_durations.append(d)
            sleep_syscall_intervals.append((start_ts, end_ts))
        else:
            raw_storage_durations.append(d)
            storage_syscall_intervals.append((start_ts, end_ts))
            if "fsync" in name or "fdatasync" in name:
                fsync_count += 1
            elif "read" in name:
                read_count += 1
            elif "write" in name:
                write_count += 1

    storage_syscall_count = len(storage_syscall_intervals)
    raw_syscall_sum_ns = sum(raw_storage_durations)
    max_syscall_duration_ns = max(raw_storage_durations) if raw_storage_durations else 0

    # Non-overlapping storage syscall union clipped to operation window [op.start_ns, op.end_ns]
    non_overlap_storage_ns = compute_interval_union(
        storage_syscall_intervals,
        clip_min=op.start_ns,
        clip_max=op.end_ns,
    )
    syscall_duration_ratio = min(max(non_overlap_storage_ns / wall_duration_ns, 0.0), 1.0)

    # Voluntary sleep syscall duration
    non_overlap_sleep_ns = compute_interval_union(
        sleep_syscall_intervals,
        clip_min=op.start_ns,
        clip_max=op.end_ns,
    )
    sleep_syscall_ratio = min(max(non_overlap_sleep_ns / wall_duration_ns, 0.0), 1.0)

    # --- 2. Block Layer Features (Target Attributed vs Background) ---
    target_issues = [b for b in cw.block_events if "ISSUE" in b.event_type]
    target_completes = [b for b in cw.block_events if "COMPLETE" in b.event_type]
    target_block_bytes = sum(b.bytes_count for b in cw.block_events)
    target_block_errors = sum(1 for b in target_completes if b.error != 0)

    target_block_issue_count = len(target_issues)
    target_block_complete_count = len(target_completes)
    has_target_block_activity = 1 if (target_block_issue_count > 0 or target_block_complete_count > 0 or target_block_bytes > 0) else 0

    # Background / Unrelated block activity in the same window
    bg_events = getattr(cw, "background_block_events", [])
    background_block_count = len(bg_events)
    background_block_bytes = sum(b.bytes_count for b in bg_events)
    has_background_block_activity = 1 if (background_block_count > 0 or background_block_bytes > 0) else 0

    # --- 3. Scheduler Layer Features ---
    runnable_wait_ns = 0
    sched_switch_count = 0
    sched_wakeup_count = 0
    preemption_count = 0
    explicit_on_cpu_durations = 0

    # Track off-CPU blocked intervals (where task was scheduled off with prev_state != 0)
    sorted_sched = sorted(cw.sched_events, key=lambda x: x.timestamp_ns)
    off_cpu_intervals = []
    on_cpu_intervals = []
    last_switch_out_ts = None
    last_switch_in_ts = None

    for sc in sorted_sched:
        if "WAKEUP" in sc.event_type:
            sched_wakeup_count += 1
            if last_switch_out_ts is not None:
                off_cpu_intervals.append((last_switch_out_ts, sc.timestamp_ns))
                last_switch_out_ts = None
        elif "SWITCH" in sc.event_type:
            sched_switch_count += 1
            if sc.is_on_cpu:
                runnable_wait_ns += max(sc.runnable_delay_ns, 0)
                last_switch_in_ts = sc.timestamp_ns
                if last_switch_out_ts is not None:
                    off_cpu_intervals.append((last_switch_out_ts, sc.timestamp_ns))
                    last_switch_out_ts = None
            else:
                if sc.prev_state == 0:
                    preemption_count += 1
                else:
                    # Task voluntarily blocked off-CPU (sleep, lock, or wait)
                    last_switch_out_ts = sc.timestamp_ns
                if last_switch_in_ts is not None:
                    on_cpu_intervals.append((last_switch_in_ts, sc.timestamp_ns))
                    last_switch_in_ts = None
                if getattr(sc, "on_cpu_duration_ns", 0) > 0:
                    explicit_on_cpu_durations += sc.on_cpu_duration_ns

    # Clip runnable wait to wall duration
    clipped_runnable_wait_ns = min(runnable_wait_ns, wall_duration_ns)
    sched_wait_ratio = min(max(clipped_runnable_wait_ns / wall_duration_ns, 0.0), 1.0)

    # Measured off-CPU blocked time
    measured_off_cpu_ns = compute_interval_union(off_cpu_intervals, clip_min=op.start_ns, clip_max=op.end_ns)
    total_off_cpu_blocked_ns = max(measured_off_cpu_ns, non_overlap_sleep_ns)
    off_cpu_blocked_ratio = min(max(total_off_cpu_blocked_ns / wall_duration_ns, 0.0), 1.0)

    # Measured on-CPU execution time
    measured_on_cpu_ns = compute_interval_union(on_cpu_intervals, clip_min=op.start_ns, clip_max=op.end_ns)
    if measured_on_cpu_ns == 0 and explicit_on_cpu_durations > 0:
        measured_on_cpu_ns = min(explicit_on_cpu_durations, wall_duration_ns)

    # --- 4. Observed On-CPU and Unobserved / Gap Accounting ---
    is_empty_window = 1 if (storage_syscall_count == 0 and sleep_syscall_count == 0 and has_target_block_activity == 0 and has_background_block_activity == 0 and sched_switch_count == 0) else 0

    if is_empty_window:
        observed_on_cpu_ns = 0
        on_cpu_ratio = 0.0
        unobserved_ns = wall_duration_ns
        unobserved_ratio = 1.0
    else:
        if measured_on_cpu_ns > 0:
            observed_on_cpu_ns = measured_on_cpu_ns
        else:
            # If off-CPU blocked delay accounts for the time, observed on-CPU is zero
            if total_off_cpu_blocked_ns >= (wall_duration_ns - clipped_runnable_wait_ns - non_overlap_storage_ns):
                observed_on_cpu_ns = 0
            else:
                accounted_non_cpu = min(non_overlap_storage_ns + clipped_runnable_wait_ns + total_off_cpu_blocked_ns, wall_duration_ns)
                observed_on_cpu_ns = max(0, wall_duration_ns - accounted_non_cpu)

        on_cpu_ratio = min(max(observed_on_cpu_ns / wall_duration_ns, 0.0), 1.0)

        # Honest accounting: unaccounted gap is unknown/unobserved telemetry
        accounted_total_ns = min(observed_on_cpu_ns + non_overlap_storage_ns + clipped_runnable_wait_ns + total_off_cpu_blocked_ns, wall_duration_ns)
        unobserved_ns = max(0, wall_duration_ns - accounted_total_ns)
        unobserved_ratio = min(max(unobserved_ns / wall_duration_ns, 0.0), 1.0)

    # Dropped event rate
    tot_telemetry = storage_syscall_count + sleep_syscall_count + target_block_issue_count + target_block_complete_count + sched_switch_count
    dropped_cnt = cw.dropped_events_count
    emitted_cnt = max(int(getattr(op, "total_events_emitted", 0) or 0), 0)
    if emitted_cnt + dropped_cnt > 0:
        dropped_rate = dropped_cnt / (emitted_cnt + dropped_cnt)
    else:
        dropped_rate = (dropped_cnt / (dropped_cnt + tot_telemetry)) if (dropped_cnt + tot_telemetry) > 0 else 0.0

    return {
        "trial_id": op.trial_id,
        "parent_trial_id": parent_trial_id,
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
        "syscall_count": storage_syscall_count,
        "raw_syscall_sum_ns": raw_syscall_sum_ns,
        "non_overlap_syscall_ns": non_overlap_storage_ns,
        "max_syscall_duration_ns": max_syscall_duration_ns,
        "syscall_duration_ratio": round(syscall_duration_ratio, 4),
        "fsync_count": fsync_count,
        "read_count": read_count,
        "write_count": write_count,

        # Sleep negative control features
        "sleep_syscall_count": sleep_syscall_count,
        "sleep_syscall_duration_ns": non_overlap_sleep_ns,
        "sleep_syscall_ratio": round(sleep_syscall_ratio, 4),

        # Block layer features (target vs background)
        "block_issue_count": target_block_issue_count,
        "block_complete_count": target_block_complete_count,
        "block_total_bytes": target_block_bytes,
        "has_block_activity": has_target_block_activity,
        "has_target_block_activity": has_target_block_activity,
        "target_block_bytes": target_block_bytes,
        "has_background_block_activity": has_background_block_activity,
        "background_block_count": background_block_count,
        "background_block_bytes": background_block_bytes,
        "block_errors": target_block_errors,

        # Sched features
        "sched_switch_count": sched_switch_count,
        "sched_wakeup_count": sched_wakeup_count,
        "preemption_count": preemption_count,
        "runnable_wait_ns": clipped_runnable_wait_ns,
        "sched_wait_ratio": round(sched_wait_ratio, 4),
        "off_cpu_blocked_ns": total_off_cpu_blocked_ns,
        "off_cpu_blocked_ratio": round(off_cpu_blocked_ratio, 4),
        "measured_on_cpu_ns": measured_on_cpu_ns,

        # Accounting & Data Quality
        "observed_on_cpu_ns": observed_on_cpu_ns,
        "on_cpu_ratio": round(on_cpu_ratio, 4),
        "unobserved_ns": unobserved_ns,
        "unobserved_ratio": round(unobserved_ratio, 4),
        "is_empty_window": is_empty_window,
        "dropped_event_count": dropped_cnt,
        "total_events_emitted": emitted_cnt,
        "dropped_event_rate": round(dropped_rate, 4),
    }

def extract_features_table(correlated_windows: List[WindowCorrelatedEvents]) -> pd.DataFrame:
    """Extracts features for all correlated windows into a pandas DataFrame."""
    records = [extract_features_from_correlated_window(cw) for cw in correlated_windows]
    if not records:
        return pd.DataFrame()
    return pd.DataFrame(records)
