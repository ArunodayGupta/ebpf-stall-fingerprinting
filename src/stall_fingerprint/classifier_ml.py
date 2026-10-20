"""
Lightweight Interpretable Machine Learning Classifier for Stall Fingerprinting.

Implements:
- Decision Tree with controlled max_depth (e.g., 3-4) for full interpretability
- Grouped Train/Test split by trial_id to strictly prevent execution data leakage
- Insufficient data detection and graceful fallback
- Feature importance analysis and tree rule extraction
"""

import logging
from typing import Dict, Any, List, Optional, Tuple
import pandas as pd
import numpy as np
from sklearn.tree import DecisionTreeClassifier, export_text
from sklearn.model_selection import GroupShuffleSplit
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline

logger = logging.getLogger("stall_fingerprint.classifier_ml")

ML_FEATURE_COLS = [
    "syscall_duration_ratio",
    "has_block_activity",
    "block_total_bytes",
    "sched_wait_ratio",
    "on_cpu_ratio",
    "unobserved_ratio",
    "syscall_count",
    "sched_switch_count",
    "fsync_count",
]

class LightweightMLClassifier:
    """
    Interpretable Decision Tree classifier trained strictly on run-level grouped splits.
    """

    def __init__(
        self,
        max_depth: int = 3,
        random_state: int = 42,
        min_samples_per_class: int = 2,
    ):
        self.max_depth = max_depth
        self.random_state = random_state
        self.min_samples_per_class = min_samples_per_class
        self.model: Optional[DecisionTreeClassifier] = None
        self.is_fitted = False
        self.feature_names = ML_FEATURE_COLS
        self.classes_ = []

    def check_data_sufficiency(self, df: pd.DataFrame, target_col: str = "expected_label") -> Tuple[bool, str]:
        if df.empty or len(df) < 8:
            return False, f"Insufficient total samples: {len(df)} < 8"

        class_counts = df[target_col].value_counts()
        if len(class_counts) < 2:
            return False, f"Fewer than 2 distinct classes present: {list(class_counts.keys())}"

        min_cnt = class_counts.min()
        if min_cnt < self.min_samples_per_class:
            return False, f"Class {class_counts.idxmin()} has only {min_cnt} samples (requires >= {self.min_samples_per_class})"

        return True, "Data sufficient for training."

    def split_data_by_trial(
        self,
        df: pd.DataFrame,
        test_size: float = 0.30,
        group_col: str = "trial_id",
        target_col: str = "expected_label",
    ) -> Tuple[pd.DataFrame, pd.DataFrame]:
        """
        Grouped split guaranteeing all samples from a trial reside strictly in either train or test.
        """
        groups = df[group_col].values
        gss = GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=self.random_state)
        train_idx, test_idx = next(gss.split(df, groups=groups))

        train_df = df.iloc[train_idx].copy()
        test_df = df.iloc[test_idx].copy()
        return train_df, test_df

    def fit(self, train_df: pd.DataFrame, target_col: str = "expected_label") -> bool:
        sufficient, reason = self.check_data_sufficiency(train_df, target_col=target_col)
        if not sufficient:
            logger.warning(f"Skipping ML training: {reason}")
            self.is_fitted = False
            return False

        # Prepare X and y
        X_train = train_df[self.feature_names].fillna(0.0).values
        y_train = train_df[target_col].values

        self.model = DecisionTreeClassifier(
            max_depth=self.max_depth,
            random_state=self.random_state,
            class_weight="balanced",
        )
        self.model.fit(X_train, y_train)
        self.is_fitted = True
        self.classes_ = list(self.model.classes_)
        logger.info(f"Fitted Decision Tree on {len(train_df)} samples. Classes: {self.classes_}")
        return True

    def predict(self, df: pd.DataFrame) -> List[str]:
        if not self.is_fitted or self.model is None:
            return ["indeterminate"] * len(df)

        X = df[self.feature_names].fillna(0.0).values
        return list(self.model.predict(X))

    def get_feature_importances(self) -> Dict[str, float]:
        if not self.is_fitted or self.model is None:
            return {}
        return dict(zip(self.feature_names, [round(float(v), 4) for v in self.model.feature_importances_]))

    def export_rules(self) -> str:
        if not self.is_fitted or self.model is None:
            return "Model not fitted."
        return export_text(self.model, feature_names=self.feature_names)
