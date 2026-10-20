"""
Single-Source Baselines and Feature-Masked Classifiers.

Implements:
1. Baseline 1: Syscall-Duration-Only Classifier (Strictly masks block & scheduler features)
2. Baseline 2: Block-I/O-Only Classifier (Strictly masks syscall & scheduler features)
3. Baseline 3: Scheduler-Only Classifier (Strictly masks syscall & block features)
4. Fused Classifier: Combines all three layers
"""

from typing import Dict, Any, List
from stall_fingerprint.classifier_rules import (
    LABEL_IO_WAIT,
    LABEL_SCHED_WAIT,
    LABEL_CPU_SYSCALL,
    LABEL_INDETERMINATE,
    RulePrediction,
    RuleBasedClassifier,
)

class SyscallOnlyClassifier:
    """Baseline 1: Relies strictly on syscall duration metrics."""

    ALLOWED_FEATURES = {
        "syscall_count",
        "raw_syscall_sum_ns",
        "non_overlap_syscall_ns",
        "max_syscall_duration_ns",
        "syscall_duration_ratio",
        "wall_duration_ns",
        "is_empty_window",
    }

    def __init__(self, syscall_ratio_thresh: float = 0.40):
        self.syscall_ratio_thresh = syscall_ratio_thresh

    def predict_sample(self, features: Dict[str, Any]) -> RulePrediction:
        # Strictly enforce feature isolation
        masked = {k: features.get(k) for k in self.ALLOWED_FEATURES}

        is_empty = masked.get("is_empty_window", 0)
        sys_ratio = masked.get("syscall_duration_ratio", 0.0)

        if is_empty or masked.get("syscall_count", 0) == 0:
            return RulePrediction(
                predicted_label=LABEL_INDETERMINATE,
                confidence=0.50,
                rule_fired="BASE_SYSCALL_EMPTY",
                contributing_signals={"syscall_ratio": sys_ratio},
                explanation="No syscalls observed in window.",
            )

        if sys_ratio >= self.syscall_ratio_thresh:
            return RulePrediction(
                predicted_label=LABEL_IO_WAIT,
                confidence=0.70,
                rule_fired="BASE_SYSCALL_HIGH_DURATION",
                contributing_signals={"syscall_ratio": sys_ratio},
                explanation=f"Syscall duration ratio ({sys_ratio:.2f}) indicates potential I/O wait.",
            )
        elif sys_ratio < 0.20:
            return RulePrediction(
                predicted_label=LABEL_CPU_SYSCALL,
                confidence=0.60,
                rule_fired="BASE_SYSCALL_LOW_DURATION",
                contributing_signals={"syscall_ratio": sys_ratio},
                explanation=f"Syscall duration is low ({sys_ratio:.2f}); assuming CPU execution.",
            )

        return RulePrediction(
            predicted_label=LABEL_INDETERMINATE,
            confidence=0.40,
            rule_fired="BASE_SYSCALL_INDETERMINATE",
            contributing_signals={"syscall_ratio": sys_ratio},
            explanation="Syscall ratio in indeterminate range.",
        )

    def predict_dataframe(self, df) -> List[str]:
        return [self.predict_sample(r.to_dict()).predicted_label for _, r in df.iterrows()]

class BlockOnlyClassifier:
    """Baseline 2: Relies strictly on block-layer request events."""

    ALLOWED_FEATURES = {
        "block_issue_count",
        "block_complete_count",
        "block_total_bytes",
        "has_block_activity",
        "wall_duration_ns",
    }

    def predict_sample(self, features: Dict[str, Any]) -> RulePrediction:
        masked = {k: features.get(k) for k in self.ALLOWED_FEATURES}
        has_block = masked.get("has_block_activity", 0)
        bytes_cnt = masked.get("block_total_bytes", 0)

        if has_block or bytes_cnt > 0:
            return RulePrediction(
                predicted_label=LABEL_IO_WAIT,
                confidence=0.75,
                rule_fired="BASE_BLOCK_ACTIVITY_DETECTED",
                contributing_signals={"block_bytes": bytes_cnt},
                explanation="Block-layer device I/O detected during operation window.",
            )

        return RulePrediction(
            predicted_label=LABEL_INDETERMINATE,
            confidence=0.40,
            rule_fired="BASE_BLOCK_NO_ACTIVITY",
            contributing_signals={"block_bytes": bytes_cnt},
            explanation="No block-layer requests observed; cannot distinguish CPU from scheduler or sleep.",
        )

    def predict_dataframe(self, df) -> List[str]:
        return [self.predict_sample(r.to_dict()).predicted_label for _, r in df.iterrows()]

class SchedulerOnlyClassifier:
    """Baseline 3: Relies strictly on scheduler telemetry (runnable delays)."""

    ALLOWED_FEATURES = {
        "sched_switch_count",
        "sched_wakeup_count",
        "preemption_count",
        "runnable_wait_ns",
        "sched_wait_ratio",
        "wall_duration_ns",
    }

    def __init__(self, sched_wait_thresh: float = 0.40):
        self.sched_wait_thresh = sched_wait_thresh

    def predict_sample(self, features: Dict[str, Any]) -> RulePrediction:
        masked = {k: features.get(k) for k in self.ALLOWED_FEATURES}
        wait_ratio = masked.get("sched_wait_ratio", 0.0)

        if wait_ratio >= self.sched_wait_thresh:
            return RulePrediction(
                predicted_label=LABEL_SCHED_WAIT,
                confidence=0.80,
                rule_fired="BASE_SCHED_RUNNABLE_WAIT",
                contributing_signals={"sched_wait_ratio": wait_ratio},
                explanation=f"High runnable wait delay ({wait_ratio:.2f}) indicates scheduler contention.",
            )

        return RulePrediction(
            predicted_label=LABEL_INDETERMINATE,
            confidence=0.40,
            rule_fired="BASE_SCHED_INCONCLUSIVE",
            contributing_signals={"sched_wait_ratio": wait_ratio},
            explanation="Runnable wait low; scheduler alone cannot distinguish storage I/O from CPU work.",
        )

    def predict_dataframe(self, df) -> List[str]:
        return [self.predict_sample(r.to_dict()).predicted_label for _, r in df.iterrows()]
