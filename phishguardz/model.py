from __future__ import annotations

import os
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import IsolationForest
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    average_precision_score,
    brier_score_loss,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.feature_extraction.text import TfidfVectorizer

from .features import extract_url_features, registered_domain, risk_indicators

NUMERIC_FEATURES = [
    "url_length",
    "hostname_length",
    "registered_domain_length",
    "path_length",
    "query_length",
    "subdomain_count",
    "digit_count",
    "hyphen_count",
    "underscore_count",
    "dot_count",
    "slash_count",
    "special_character_count",
    "ip_address_host",
    "at_symbol",
    "double_dot",
    "https",
    "entropy",
    "suspicious_tld",
    "suspicious_keyword_count",
    "brand_hint_count",
    "brand_matches_registered_domain",
    "brand_in_mismatched_domain",
    "digit_ratio",
    "hostname_has_punycode",
    "host_path_separator_count",
]


def _new_classifier() -> Pipeline:
    features = ColumnTransformer(
        transformers=[
            (
                "url_characters",
                TfidfVectorizer(
                    analyzer="char",
                    ngram_range=(2, 5),
                    min_df=2,
                    max_features=100_000,
                    sublinear_tf=True,
                ),
                "url",
            ),
            ("numeric", StandardScaler(with_mean=False), NUMERIC_FEATURES),
        ],
        remainder="drop",
    )
    return Pipeline(
        [
            ("features", features),
            (
                "classifier",
                LogisticRegression(
                    C=1.0,
                    class_weight="balanced",
                    max_iter=2_000,
                    random_state=42,
                ),
            ),
        ]
    )


def _logit(probabilities: np.ndarray) -> np.ndarray:
    clipped = np.clip(probabilities, 1e-6, 1 - 1e-6)
    return np.log(clipped / (1 - clipped)).reshape(-1, 1)


class PhishGuardModel:
    def __init__(self, model_path: str = "models/phishguardz.joblib") -> None:
        self.model_path = model_path
        self.model: Pipeline | None = None
        self.calibrator: LogisticRegression | None = None
        self.ood_model: IsolationForest | None = None
        self.ood_reference_scores: np.ndarray = np.array([])
        self.metadata: dict[str, Any] = {}

    @staticmethod
    def _normalize_labels(labels: pd.Series) -> np.ndarray:
        normalized = labels.astype(str).str.strip().str.lower()
        mapping = {
            "phishing": 1,
            "malicious": 1,
            "fraud": 1,
            "1": 1,
            "legitimate": 0,
            "benign": 0,
            "safe": 0,
            "0": 0,
        }
        unknown = sorted(set(normalized) - set(mapping))
        if unknown:
            raise ValueError(f"Unknown label value(s): {unknown}")
        return normalized.map(mapping).to_numpy(dtype=int)

    @staticmethod
    def load_dataset(dataset_path: str) -> pd.DataFrame:
        if not os.path.isfile(dataset_path):
            raise FileNotFoundError(f"Dataset not found: {dataset_path}")
        df = pd.read_csv(dataset_path)
        missing = {"url", "label"} - set(df.columns)
        if missing:
            raise ValueError(f"Dataset is missing required columns: {sorted(missing)}")
        df = df[["url", "label"]].copy()
        df["label"] = PhishGuardModel._normalize_labels(df["label"])
        df["url"] = df["url"].astype(str).str.strip()
        df["domain"] = df["url"].map(registered_domain)
        df = df.drop_duplicates(subset=["url", "label"]).reset_index(drop=True)

        conflicting = df.groupby("domain")["label"].nunique()
        conflicting_domains = set(conflicting[conflicting > 1].index)
        if conflicting_domains:
            df = df[~df["domain"].isin(conflicting_domains)].copy()
        if df.empty:
            raise ValueError("No unambiguous valid URL records remain in the dataset.")
        return df.reset_index(drop=True)

    @staticmethod
    def _features(urls: pd.Series | list[str]) -> pd.DataFrame:
        return pd.DataFrame([extract_url_features(url) for url in urls])

    @staticmethod
    def _split_by_domain(
        X: pd.DataFrame, y: np.ndarray, groups: np.ndarray
    ) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
        if len(np.unique(groups)) < 10:
            raise ValueError("At least 10 unique registered domains are required.")
        if min(np.bincount(y, minlength=2)) < 5:
            raise ValueError("At least 5 examples from each class are required.")

        outer = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=42)
        train_validation_idx, test_idx = next(outer.split(X, y, groups))
        inner = StratifiedGroupKFold(n_splits=4, shuffle=True, random_state=43)
        train_relative_idx, calibration_relative_idx = next(
            inner.split(
                X.iloc[train_validation_idx],
                y[train_validation_idx],
                groups[train_validation_idx],
            )
        )
        train_idx = train_validation_idx[train_relative_idx]
        calibration_idx = train_validation_idx[calibration_relative_idx]

        for split_name, indices in (
            ("train", train_idx),
            ("calibration", calibration_idx),
            ("test", test_idx),
        ):
            if len(np.unique(y[indices])) != 2:
                raise ValueError(f"The domain-disjoint {split_name} split lacks one class.")
        if (
            set(groups[train_idx]) & set(groups[calibration_idx])
            or set(groups[train_idx]) & set(groups[test_idx])
            or set(groups[calibration_idx]) & set(groups[test_idx])
        ):
            raise RuntimeError("Domain leakage detected between train, calibration, and test.")
        return train_idx, calibration_idx, test_idx

    def train(self, dataset_path: str) -> dict[str, Any]:
        df = self.load_dataset(dataset_path)
        X = self._features(df["url"])
        y = df["label"].to_numpy(dtype=int)
        groups = df["domain"].to_numpy()
        train_idx, calibration_idx, test_idx = self._split_by_domain(X, y, groups)

        candidate = _new_classifier()
        candidate.fit(X.iloc[train_idx], y[train_idx])
        calibration_scores = candidate.predict_proba(X.iloc[calibration_idx])[:, 1]
        self.calibrator = LogisticRegression(C=1e6, solver="lbfgs", random_state=42)
        self.calibrator.fit(_logit(calibration_scores), y[calibration_idx])

        test_scores = candidate.predict_proba(X.iloc[test_idx])[:, 1]
        test_probabilities = self.calibrator.predict_proba(_logit(test_scores))[:, 1]
        test_predictions = (test_probabilities >= 0.5).astype(int)
        y_test = y[test_idx]
        true_negative, false_positive, false_negative, true_positive = confusion_matrix(
            y_test, test_predictions, labels=[0, 1]
        ).ravel()
        bin_edges = np.linspace(0.0, 1.0, 11)
        expected_calibration_error = 0.0
        for lower, upper in zip(bin_edges[:-1], bin_edges[1:]):
            in_bin = (test_probabilities >= lower) & (test_probabilities < upper)
            if np.any(in_bin):
                expected_calibration_error += float(np.mean(in_bin)) * abs(
                    float(np.mean(test_probabilities[in_bin]))
                    - float(np.mean(y_test[in_bin]))
                )
        metrics = {
            "train_domains": int(len(np.unique(groups[train_idx]))),
            "calibration_domains": int(len(np.unique(groups[calibration_idx]))),
            "test_domains": int(len(np.unique(groups[test_idx]))),
            "train_samples": int(len(train_idx)),
            "calibration_samples": int(len(calibration_idx)),
            "test_samples": int(len(test_idx)),
            "test_phishing_samples": int(np.sum(y_test == 1)),
            "test_legitimate_samples": int(np.sum(y_test == 0)),
            "test_precision": float(precision_score(y_test, test_predictions, zero_division=0)),
            "test_recall": float(recall_score(y_test, test_predictions, zero_division=0)),
            "test_f1": float(f1_score(y_test, test_predictions, zero_division=0)),
            "test_false_positive_rate": float(
                false_positive / max(1, false_positive + true_negative)
            ),
            "test_false_negative_rate": float(
                false_negative / max(1, false_negative + true_positive)
            ),
            "test_roc_auc": float(roc_auc_score(y_test, test_probabilities)),
            "test_pr_auc": float(average_precision_score(y_test, test_probabilities)),
            "test_brier_score": float(brier_score_loss(y_test, test_probabilities)),
            "test_expected_calibration_error_10_bins": expected_calibration_error,
        }

        self.model = candidate
        numeric_training = X.iloc[train_idx][NUMERIC_FEATURES]
        self.ood_model = IsolationForest(
            contamination="auto",
            n_estimators=200,
            random_state=42,
        )
        self.ood_model.fit(numeric_training)
        self.ood_reference_scores = np.sort(
            self.ood_model.score_samples(numeric_training)
        )

        self.metadata = {
            "dataset": os.path.abspath(dataset_path),
            "trained_samples": int(len(train_idx)),
            "trained_domains": int(len(np.unique(groups[train_idx]))),
            "calibration_samples": int(len(calibration_idx)),
            "calibration_domains": int(len(np.unique(groups[calibration_idx]))),
            "class_counts": {
                "legitimate": int(np.sum(y[train_idx] == 0)),
                "phishing": int(np.sum(y[train_idx] == 1)),
            },
            "split_strategy": "stratified registered-domain-disjoint train/calibration/test",
            "model_type": "character n-gram TF-IDF + URL lexical features + calibrated logistic regression",
            "feature_count": int(len(NUMERIC_FEATURES)),
            "ood_method": "isolation forest percentile against training URL feature distribution",
            "metrics": metrics,
        }
        self.save(self.model_path)
        return metrics

    def save(self, output_path: str) -> None:
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        joblib.dump(
            {
                "model": self.model,
                "calibrator": self.calibrator,
                "ood_model": self.ood_model,
                "ood_reference_scores": self.ood_reference_scores,
                "metadata": self.metadata,
            },
            output_path,
        )

    @classmethod
    def load(cls, model_path: str) -> "PhishGuardModel":
        if not os.path.isfile(model_path):
            raise FileNotFoundError(f"Model file not found: {model_path}")
        bundle = joblib.load(model_path)
        instance = cls(model_path=model_path)
        instance.model = bundle["model"]
        instance.calibrator = bundle["calibrator"]
        instance.ood_model = bundle["ood_model"]
        instance.ood_reference_scores = bundle["ood_reference_scores"]
        instance.metadata = bundle["metadata"]
        return instance

    @staticmethod
    def _risk_level(probability: float) -> str:
        if probability >= 0.85:
            return "CRITICAL"
        if probability >= 0.65:
            return "HIGH"
        if probability >= 0.35:
            return "MEDIUM"
        return "LOW"

    def score_url(self, url: str) -> dict[str, Any]:
        if self.model is None or self.calibrator is None or self.ood_model is None:
            raise ValueError("Model is not trained or loaded.")
        features = self._features([url])
        raw_probability = self.model.predict_proba(features)[:, 1]
        probability = float(
            self.calibrator.predict_proba(_logit(raw_probability))[0, 1]
        )
        numeric = features[NUMERIC_FEATURES]
        anomaly_score = float(self.ood_model.score_samples(numeric)[0])
        ood_score = float(
            1.0
            - np.searchsorted(self.ood_reference_scores, anomaly_score, side="right")
            / max(1, len(self.ood_reference_scores))
        )
        return {
            "url": url,
            "risk_level": self._risk_level(probability),
            "phishing_probability": round(probability, 4),
            "model_confidence": round(max(probability, 1.0 - probability), 4),
            "is_ood": bool(ood_score >= 0.95),
            "ood_score": round(ood_score, 4),
            "indicators": risk_indicators(url),
        }


def train_and_save(
    dataset_path: str, output_path: str = "models/phishguardz.joblib"
) -> dict[str, Any]:
    model = PhishGuardModel(model_path=output_path)
    return model.train(dataset_path)
