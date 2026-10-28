"""
Rule-Based Transparent Classifier for Stall Fingerprinting.

Classifies application operations into four categories:
1. io_wait_dominated
2. scheduler_wait_dominated
3. cpu_syscall_dominated
4. indeterminate

Returns structured explanations, contributing signals, and confidence scores.
"""

from typing import Dict, Any, Tuple, Optional
from dataclasses import dataclass, asdict

# Target classification taxonomy constants
LABEL_IO_WAIT = "io_wait_dominated"
LABEL_SCHED_WAIT = "scheduler_wait_dominated"
LABEL_CPU_SYSCALL = "cpu_syscall_dominated"
LABEL_INDETERMINATE = "indeterminate"

VALID_LABELS = [
    LABEL_IO_WAIT,
    LABEL_SCHED_WAIT,
    LABEL_CPU_SYSCALL,
    LABEL_INDETERMINATE,
]

@dataclass
class RulePrediction:
    predicted_label: str
    confidence: float
    rule_fired: str
    contributing_signals: Dict[str, Any]
    explanation: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

class RuleBasedClassifier:
    """
    Transparent rule-based classifier utilizing fused syscall, block-layer, and scheduler features.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        cfg = config or {}
        # Thresholds loaded from configuration or sensible defaults
        self.min_stall_duration_ns = cfg.get("min_stall_duration_ns", 1_000_000)      # 1ms
        self.io_syscall_ratio_thresh = cfg.get("io_syscall_ratio_thresh", 0.40)       # 40%
        self.io_block_min_bytes = cfg.get("io_block_min_bytes", 512)
        self.sched_wait_ratio_thresh = cfg.get("sched_wait_ratio_thresh", 0.40)       # 40%
        self.cpu_on_cpu_ratio_thresh = cfg.get("cpu_on_cpu_ratio_thresh", 0.60)       # 60%
        self.indeterminate_unobserved = cfg.get("indeterminate_unobserved_ratio", 0.50) # 50%
        self.max_dropped_event_rate = cfg.get("max_dropped_event_rate", 0.15)         # 15%

    def predict_sample(self, features: Dict[str, Any]) -> RulePrediction:
        wall_ns = features.get("wall_duration_ns", 0)
        syscall_ratio = features.get("syscall_duration_ratio", 0.0)
        sched_wait_ratio = features.get("sched_wait_ratio", 0.0)
        on_cpu_ratio = features.get("on_cpu_ratio", 0.0)
        unobserved_ratio = features.get("unobserved_ratio", 0.0)
        off_cpu_blocked_ratio = features.get("off_cpu_blocked_ratio", 0.0)
        sleep_syscall_ratio = features.get("sleep_syscall_ratio", 0.0)

        has_target_block = features.get("has_target_block_activity", features.get("has_block_activity", 0))
        target_bytes = features.get("target_block_bytes", features.get("block_total_bytes", 0))
        has_bg_block = features.get("has_background_block_activity", 0)
        bg_bytes = features.get("background_block_bytes", 0)

        fsync_cnt = features.get("fsync_count", 0)
        dropped_cnt = features.get("dropped_event_count", 0)
        dropped_rate = features.get("dropped_event_rate", 0.0)
        is_empty = features.get("is_empty_window", 0)

        contributing = {
            "wall_duration_ms": round(wall_ns / 1_000_000, 2),
            "syscall_ratio": syscall_ratio,
            "sched_wait_ratio": sched_wait_ratio,
            "on_cpu_ratio": on_cpu_ratio,
            "off_cpu_blocked_ratio": off_cpu_blocked_ratio,
            "sleep_syscall_ratio": sleep_syscall_ratio,
            "unobserved_ratio": unobserved_ratio,
            "has_target_block": has_target_block,
            "target_bytes": target_bytes,
            "has_bg_block": has_bg_block,
            "fsync_count": fsync_cnt,
            "dropped_event_rate": dropped_rate,
        }

        # Rule 0a: Excessive Telemetry Drop Rate Abstention
        if dropped_rate >= self.max_dropped_event_rate:
            return RulePrediction(
                predicted_label=LABEL_INDETERMINATE,
                confidence=0.95,
                rule_fired="RULE_ABSTAIN_EXCESSIVE_DROPS",
                contributing_signals=contributing,
                explanation=(
                    f"Excessive telemetry event loss ({dropped_rate:.2%}) exceeds reliable attribution "
                    f"threshold ({self.max_dropped_event_rate:.2%}). Result marked indeterminate."
                ),
            )

        # Rule 0b: Voluntary Sleep / Negative-Control Abstention
        max_sleep_signal = max(off_cpu_blocked_ratio, sleep_syscall_ratio)
        if max_sleep_signal >= 0.40:
            return RulePrediction(
                predicted_label=LABEL_INDETERMINATE,
                confidence=0.95,
                rule_fired="RULE_OFF_CPU_VOLUNTARY_SLEEP",
                contributing_signals=contributing,
                explanation=(
                    f"Task spent dominant time voluntarily blocked off-CPU ({max_sleep_signal:.2f}), "
                    "not runnable or stalled on storage. Validated negative control (abstention)."
                ),
            )

        # Rule 0c: Empty Window or Dominant Unobserved Gap Abstention
        if is_empty == 1 or unobserved_ratio >= self.indeterminate_unobserved:
            return RulePrediction(
                predicted_label=LABEL_INDETERMINATE,
                confidence=0.90,
                rule_fired="RULE_ABSTAIN_UNOBSERVED_TELEMETRY",
                contributing_signals=contributing,
                explanation=(
                    f"Telemetric gap: unobserved ratio ({unobserved_ratio:.2f}) exceeds threshold "
                    f"({self.indeterminate_unobserved:.2f}) or empty telemetry window. "
                    "Evidence insufficient to substantiate I/O, CPU, or scheduler attribution."
                ),
            )

        # Rule 1: High Scheduler Runnable Wait Delay Dominance
        if sched_wait_ratio >= self.sched_wait_ratio_thresh and sched_wait_ratio >= syscall_ratio:
            conf = min(0.50 + sched_wait_ratio / 2.0, 0.98)
            return RulePrediction(
                predicted_label=LABEL_SCHED_WAIT,
                confidence=round(conf, 2),
                rule_fired="RULE_SCHED_WAIT_DOMINATED",
                contributing_signals=contributing,
                explanation=(
                    f"Task experienced significant runnable delay (wait ratio: {sched_wait_ratio:.2f} >= "
                    f"{self.sched_wait_ratio_thresh:.2f}), indicating CPU runqueue contention."
                ),
            )

        # Rule 2: I/O Wait Dominance (Syscall duration + Target-attributed Block layer corroboration or sync calls)
        if syscall_ratio >= self.io_syscall_ratio_thresh:
            if has_target_block or fsync_cnt > 0 or target_bytes >= self.io_block_min_bytes:
                conf = min(0.60 + syscall_ratio / 2.5, 0.99)
                return RulePrediction(
                    predicted_label=LABEL_IO_WAIT,
                    confidence=round(conf, 2),
                    rule_fired="RULE_IO_WAIT_FUSED",
                    contributing_signals=contributing,
                    explanation=(
                        f"Long storage syscall duration (ratio: {syscall_ratio:.2f} >= {self.io_syscall_ratio_thresh:.2f}) "
                        f"corroborated by target block I/O activity ({target_bytes} bytes, fsync={fsync_cnt})."
                    ),
                )
            elif has_bg_block > 0:
                # Concurrent background block activity present, but NOT attributable to target process
                return RulePrediction(
                    predicted_label=LABEL_INDETERMINATE,
                    confidence=0.75,
                    rule_fired="RULE_IO_AMBIGUOUS_UNATTRIBUTED_BLOCK",
                    contributing_signals=contributing,
                    explanation=(
                        f"Syscall duration was elevated ({syscall_ratio:.2f}) with concurrent system block activity "
                        f"({bg_bytes} bytes), but no block requests were attributable to the target PID. "
                        "Preserving uncertainty under cross-process background activity."
                    ),
                )
            else:
                # Long syscall without block I/O activity: cached I/O
                return RulePrediction(
                    predicted_label=LABEL_INDETERMINATE,
                    confidence=0.65,
                    rule_fired="RULE_IO_AMBIGUOUS_CACHED",
                    contributing_signals=contributing,
                    explanation=(
                        f"Syscall duration was elevated ({syscall_ratio:.2f}) but no underlying block-layer "
                        "activity was observed. Likely cached filesystem operation without device stall."
                    ),
                )

        # Rule 3: CPU/Syscall Processing Dominance
        if (
            on_cpu_ratio >= self.cpu_on_cpu_ratio_thresh
            and sched_wait_ratio < 0.20
            and syscall_ratio < 0.25
            and off_cpu_blocked_ratio < 0.20
            and sleep_syscall_ratio < 0.10
        ):
            conf = min(0.65 + on_cpu_ratio / 3.0, 0.99)
            return RulePrediction(
                predicted_label=LABEL_CPU_SYSCALL,
                confidence=round(conf, 2),
                rule_fired="RULE_CPU_PROCESSING_DOMINATED",
                contributing_signals=contributing,
                explanation=(
                    f"Measured on-CPU execution ({on_cpu_ratio:.2f} >= {self.cpu_on_cpu_ratio_thresh:.2f}) "
                    "dominated operation window with negligible scheduler wait and storage delay."
                ),
            )

        # Rule 4: Default Contradictory / Ambiguous Evidence Abstention
        return RulePrediction(
            predicted_label=LABEL_INDETERMINATE,
            confidence=0.50,
            rule_fired="RULE_AMBIGUOUS_EVIDENCE",
            contributing_signals=contributing,
            explanation=(
                "Mixed or inconclusive signals: neither I/O delay, runnable scheduling wait, "
                "nor on-CPU execution cleanly dominated the operation window."
            ),
        )

    def predict_dataframe(self, df) -> Tuple[list, list]:
        """Predicts labels and explanations for all rows in a DataFrame."""
        preds = []
        exps = []
        for _, row in df.iterrows():
            feat_dict = row.to_dict()
            res = self.predict_sample(feat_dict)
            preds.append(res.predicted_label)
            exps.append(res.explanation)
        return preds, exps
