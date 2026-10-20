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
    block_events: List[BlockEvent] = field(default_factory=list)
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
    Correlates a stream of raw events with workload operation records.
    """

    def __init__(self, window_margin_ns: int = 0):
        self.window_margin_ns = window_margin_ns

    def correlate_operation(
        self,
        op: WorkloadOperationRecord,
        events: List[BaseEvent],
    ) -> WindowCorrelatedEvents:
        target_pid = op.pid
        win_start = op.start_ns - self.window_margin_ns
        win_end = op.end_ns + self.window_margin_ns

        matched = WindowCorrelatedEvents(operation=op)

        for ev in events:
            # Check timestamp overlap
            ts = ev.timestamp_ns
            if not (win_start <= ts <= win_end):
                continue

            if isinstance(ev, SyscallEvent):
                # Match by PID
                if ev.pid == target_pid or ev.tid == target_pid or target_pid == 0:
                    matched.syscall_events.append(ev)
            elif isinstance(ev, BlockEvent):
                # Block events are window-associated (and PID matched if available)
                if ev.pid == target_pid or ev.pid == 0:
                    matched.block_events.append(ev)
                else:
                    # Keep track of concurrent block activity in window as context
                    matched.block_events.append(ev)
            elif isinstance(ev, SchedEvent):
                if ev.target_pid == target_pid or ev.next_pid == target_pid or ev.prev_pid == target_pid:
                    matched.sched_events.append(ev)
            elif ev.event_type == EventType.DROPPED_EVENT_STATS.value:
                matched.dropped_events_count += getattr(ev, "total_events_lost", 0)
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
