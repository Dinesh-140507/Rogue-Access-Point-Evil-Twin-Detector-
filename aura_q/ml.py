"""Step 5 (optional): Isolation Forest anomaly model. Trained on NORMAL windows only.
On the real board this is what you would export to TFLite/ONNX for the Adreno GPU."""
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

FEATS = ["mean", "std", "delta", "jitter_ms", "seq_jump", "deauth_rate", "n"]


def _x(feats):
    return np.array([[f[k] for k in FEATS] for f in feats], dtype=float)


class AnomalyModel:
    def __init__(self, contamination=0.005, seed=0):
        self.sc = StandardScaler()
        self.m = IsolationForest(n_estimators=100, contamination=contamination, random_state=seed)

    def fit(self, feats):
        X = self.sc.fit_transform(_x(feats))
        self.m.fit(X)
        return self

    def flags(self, feats):
        if not feats:
            return []
        return (self.m.predict(self.sc.transform(_x(feats))) == -1).tolist()
