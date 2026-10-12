import math
import random
from datetime import datetime
from typing import Any, Dict, List, Optional
import numpy as np

from ml.feature_extractor import FEATURE_NAMES, extract_features


def _c_factor(n: int) -> float:
    """Average path length of unsuccessful search in BST."""
    if n <= 1:
        return 1.0
    if n == 2:
        return 1.0
    # Euler-Mascheroni constant ~ 0.5772156649
    return 2.0 * (math.log(n - 1) + 0.5772156649) - (2.0 * (n - 1) / n)


class _ITreeNode:
    def __init__(self, left=None, right=None, split_feature=None, split_value=None, size=1):
        self.left = left
        self.right = right
        self.split_feature = split_feature
        self.split_value = split_value
        self.size = size
        self.is_leaf = left is None and right is None


def _build_itree(X: np.ndarray, current_height: int, height_limit: int) -> _ITreeNode:
    n_samples, n_features = X.shape
    if current_height >= height_limit or n_samples <= 1:
        return _ITreeNode(size=n_samples)

    # Randomly select a feature that has non-constant values
    features = list(range(n_features))
    random.shuffle(features)

    for feat in features:
        col = X[:, feat]
        min_v, max_v = float(col.min()), float(col.max())
        if min_v < max_v:
            split_val = random.uniform(min_v, max_v)
            left_mask = col < split_val
            right_mask = ~left_mask

            if left_mask.any() and right_mask.any():
                left_node = _build_itree(X[left_mask], current_height + 1, height_limit)
                right_node = _build_itree(X[right_mask], current_height + 1, height_limit)
                return _ITreeNode(
                    left=left_node,
                    right=right_node,
                    split_feature=feat,
                    split_value=split_val,
                    size=n_samples,
                )

    return _ITreeNode(size=n_samples)


def _path_length(x: np.ndarray, node: _ITreeNode, current_height: int = 0) -> float:
    if node.is_leaf:
        return current_height + _c_factor(node.size)

    feat = node.split_feature
    if x[feat] < node.split_value:
        return _path_length(x, node.left, current_height + 1)
    else:
        return _path_length(x, node.right, current_height + 1)


class PureNumpyIsolationForest:
    """Pure NumPy implementation of Isolation Forest (Liu et al., 2008)."""

    def __init__(self, n_estimators: int = 100, max_samples: int = 256, random_state: int = 42):
        self.n_estimators = n_estimators
        self.max_samples = max_samples
        self.random_state = random_state
        self.trees: List[_ITreeNode] = []
        self.c_val: float = 1.0

    def fit(self, X: np.ndarray) -> "PureNumpyIsolationForest":
        random.seed(self.random_state)
        np.random.seed(self.random_state)
        n_samples = len(X)
        subsample_size = min(self.max_samples, n_samples)
        height_limit = math.ceil(math.log2(max(subsample_size, 2)))
        self.c_val = _c_factor(subsample_size)

        self.trees = []
        for _ in range(self.n_estimators):
            idx = np.random.choice(n_samples, size=subsample_size, replace=False)
            tree = _build_itree(X[idx], 0, height_limit)
            self.trees.append(tree)

        return self

    def score_samples(self, X: np.ndarray) -> np.ndarray:
        """Returns anomaly score s in [0, 1]. Values > 0.6 indicate anomalies."""
        scores = []
        for row in X:
            avg_path = sum(_path_length(row, t) for t in self.trees) / len(self.trees)
            s = 2.0 ** (- (avg_path / max(self.c_val, 1e-6)))
            scores.append(s)
        return np.array(scores, dtype=np.float32)


class NetworkAnomalyDetector:
    """
    Unsupervised network traffic anomaly detector.
    Attempts scikit-learn IsolationForest first; automatically falls back to pure NumPy
    Isolation Forest if system Application Control / WDAC policies restrict native DLLs.
    """

    def __init__(self, contamination: float = 0.08, random_state: int = 42):
        self.contamination = contamination
        self.random_state = random_state
        self.use_sklearn = False
        self.model = None
        self.is_fitted = False

        try:
            from sklearn.ensemble import IsolationForest
            self.model = IsolationForest(
                contamination=self.contamination,
                random_state=self.random_state,
                n_estimators=100,
            )
            self.use_sklearn = True
        except (ImportError, Exception):
            self.model = PureNumpyIsolationForest(
                n_estimators=100,
                random_state=self.random_state,
            )
            self.use_sklearn = False

    def fit(self, events: List[Dict[str, Any]]) -> "NetworkAnomalyDetector":
        X, _ = extract_features(events)
        if len(X) < 10:
            return self

        self.model.fit(X)
        self.is_fitted = True
        return self

    def detect_anomalies(
        self,
        events: List[Dict[str, Any]],
        score_threshold: float = 0.60,
    ) -> List[Dict[str, Any]]:
        X, valid_events = extract_features(events)
        if len(X) < 5:
            return []

        if not self.is_fitted:
            self.model.fit(X)
            self.is_fitted = True

        if self.use_sklearn:
            raw_scores = self.model.decision_function(X)
            min_s, max_s = raw_scores.min(), raw_scores.max()
            if max_s - min_s > 1e-6:
                anomaly_scores = 1.0 - ((raw_scores - min_s) / (max_s - min_s))
            else:
                anomaly_scores = np.zeros_like(raw_scores)
            predictions = self.model.predict(X)
        else:
            anomaly_scores = self.model.score_samples(X)
            # Flag top percentile according to contamination or threshold
            threshold_val = np.percentile(anomaly_scores, 100.0 * (1.0 - self.contamination))
            predictions = np.where(anomaly_scores >= max(threshold_val, score_threshold), -1, 1)

        alerts = []
        for i, (pred, score) in enumerate(zip(predictions, anomaly_scores)):
            if pred == -1 or score >= score_threshold:
                event = valid_events[i]
                bytes_sent = event.get("bytes_sent") or 0
                bytes_recv = event.get("bytes_received") or 0
                dest_port = event.get("destination_port")

                reasons = []
                if bytes_sent > 500_000:
                    reasons.append(f"High outbound volume ({bytes_sent / 1024:.1f} KB)")
                if bytes_sent > 10 * (bytes_recv + 1):
                    reasons.append("High upload asymmetry")
                if dest_port and int(dest_port) > 1024 and int(dest_port) not in [8080, 8443]:
                    reasons.append(f"Uncommon target port ({dest_port})")
                if str(event.get("connection_state")).upper() in ["REJ", "RSTO", "S0"]:
                    reasons.append(f"Anomalous failed state ({event.get('connection_state')})")
                if not reasons:
                    reasons.append("Statistical deviation from baseline flow metrics")

                severity = "high" if score >= 0.75 else "medium"

                alerts.append({
                    "rule_id": "ML_ANOMALY_001",
                    "alert_type": "ml_traffic_anomaly",
                    "source_ip": event["source_ip"],
                    "destination_ip": event["destination_ip"],
                    "severity": severity,
                    "timestamp": event.get("timestamp") or datetime.now().isoformat(),
                    "evidence": {
                        "model": "Isolation Forest (Unsupervised)",
                        "anomaly_score": round(float(score), 3),
                        "decision": "outlier",
                        "contributing_factors": reasons,
                        "destination_port": dest_port,
                        "bytes_sent": bytes_sent,
                        "bytes_received": bytes_recv,
                        "protocol": event.get("protocol", "tcp"),
                    },
                })

        return alerts
