"""
Event Correlation Engine for eBPF Application Stall Fingerprinting.

Groups raw telemetry events (syscalls, block I/O, and scheduler transitions)
into workload operation windows defined by task PID/TID and monotonic timestamps [start_ns, end_ns].

Handles:
- Incomplete syscall pairs
- Interval clipping and non-overlapping interval union to prevent double-counting
- Window-level block I/O association
- Runnable scheduler delay accounting
- Zero-duration measurements and empty telemetry windows
"""

from typing import List, Tuple, Dict, Any, Optional
from dataclasses import dataclass, field
from stall_fingerprint.event_schema import (
    BaseEvent,
    SyscallEvent,
    BlockEvent,
    SchedEvent,
    EventType,
)
from workloads.workload_utils import WorkloadOperationRecord

@dataclass
class WindowCorrelatedEvents:
    operation: WorkloadOperationRecord
    syscall_events: List[SyscallEvent] = field(default_factory=list)
    block_events: List[BlockEvent] = field(default_factory=list)              # Target-attributed block events
    background_block_events: List[BlockEvent] = field(default_factory=list)   # Unrelated / concurrent background block events
    sched_events: List[SchedEvent] = field(default_factory=list)
    dropped_events_count: int = 0
    diagnostic_count: int = 0

def compute_interval_union(intervals: List[Tuple[int, int]], clip_min: int, clip_max: int) -> int:
    """
    Computes the total non-overlapping duration of intervals clipped within [clip_min, clip_max].
    Guarantees no double-counting of overlapping or nested measurements.
    """
    if not intervals or clip_max <= clip_min:
        return 0

    clipped = []
    for s, e in intervals:
        start = max(s, clip_min)
        end = min(e, clip_max)
        if end > start:
            clipped.append((start, end))

    if not clipped:
        return 0

    clipped.sort(key=lambda x: x[0])
    merged = [clipped[0]]

    for cur_s, cur_e in clipped[1:]:
        prev_s, prev_e = merged[-1]
        if cur_s <= prev_e:
            # Overlapping or adjacent, merge
            merged[-1] = (prev_s, max(prev_e, cur_e))
        else:
            merged.append((cur_s, cur_e))

    total_union_ns = sum(e - s for s, e in merged)
    return total_union_ns

class EventCorrelator:
    """
    Correlates a stream of raw events with workload operation records,
    strictly distinguishing target-associated evidence from background system context.
    """

    def __init__(self, window_margin_ns: int = 0, attribution_mode: str = "attributed"):
        self.window_margin_ns = window_margin_ns
        self.attribution_mode = attribution_mode  # "attributed" (default) or "all_window" (for ablation)

    def correlate_operation(
        self,
        op: WorkloadOperationRecord,
        events: List[BaseEvent],
    ) -> WindowCorrelatedEvents:
        target_pid = op.pid
        target_tid = getattr(op, "tid", target_pid)
        target_comm = getattr(op, "target_comm", "")
        win_start = op.start_ns - self.window_margin_ns
        win_end = op.end_ns + self.window_margin_ns

        trial_dropped_count = max(int(getattr(op, "dropped_events_count", 0) or 0), 0)
        has_trial_loss_totals = (
            int(getattr(op, "total_events_emitted", 0) or 0) > 0
            or trial_dropped_count > 0
        )
        matched = WindowCorrelatedEvents(
            operation=op,
            dropped_events_count=trial_dropped_count,
        )

        for ev in events:
            # Check timestamp overlap
            ts = ev.timestamp_ns
            if not (win_start <= ts <= win_end):
                continue

            if isinstance(ev, SyscallEvent):
                # Match by PID or TID
                if target_comm:
                    is_target = ev.comm == target_comm
                else:
                    is_target = ev.pid == target_pid or ev.tid == target_pid or ev.tid == target_tid or target_pid == 0
                if is_target:
                    matched.syscall_events.append(ev)
            elif isinstance(ev, BlockEvent):
                # Distinguish target-associated block I/O from background activity
                if target_comm:
                    is_target = ev.comm == target_comm
                else:
                    is_target = ev.pid == target_pid or (target_tid != 0 and ev.pid == target_tid) or target_pid == 0

                if self.attribution_mode == "all_window":
                    # Ablation mode: treat any block event in window as target evidence
                    matched.block_events.append(ev)
                else:
                    if is_target:
                        matched.block_events.append(ev)
                    else:
                        matched.background_block_events.append(ev)
            elif isinstance(ev, SchedEvent):
                if target_comm:
                    is_sched_target = ev.comm == target_comm or ev.prev_comm == target_comm or ev.next_comm == target_comm
                else:
                    is_sched_target = (
                        ev.target_pid == target_pid or
                        ev.next_pid == target_pid or
                        ev.prev_pid == target_pid or
                        (target_tid != 0 and (ev.target_pid == target_tid or ev.next_pid == target_tid or ev.prev_pid == target_tid)) or
                        target_pid == 0
                    )
                if is_sched_target:
                    matched.sched_events.append(ev)
            elif ev.event_type == EventType.DROPPED_EVENT_STATS.value:
                if not has_trial_loss_totals:
                    matched.dropped_events_count = max(
                        matched.dropped_events_count,
                        getattr(ev, "total_events_lost", 0),
                    )
            elif ev.event_type == EventType.COLLECTOR_DIAGNOSTIC.value:
                matched.diagnostic_count += 1

        return matched

    def correlate_all(
        self,
        operations: List[WorkloadOperationRecord],
        events: List[BaseEvent],
    ) -> List[WindowCorrelatedEvents]:
        results = []
        for op in operations:
            results.append(self.correlate_operation(op, events))
        return results
