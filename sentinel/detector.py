"""Unsupervised anomaly detection over per-IP behaviour."""
import json

import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest

from . import config

FEATS = ["attempts", "fail_rate", "n_users", "n_hours", "night_ratio"]

def features(df):
    g = df.groupby("src_ip")
    return g.agg(
        attempts=("success", "size"),
        fail_rate=("success", lambda s: 1 - s.astype(bool).mean()),
        n_users=("user", "nunique"),
        n_hours=("hour", "nunique"),
        night_ratio=("hour", lambda h: (h < 6).mean()),
    ).reset_index()

def train():
    f = features(pd.read_csv(config.csv_path()))
    m = IsolationForest(contamination=0.03, random_state=42, n_estimators=200).fit(f[FEATS])
    joblib.dump(m, config.model_path())
    return evaluate(f, m)

def evaluate(f, m):
    truth = set(json.load(open(config.labels_path())))
    flagged = set(f.loc[m.predict(f[FEATS]) == -1, "src_ip"])
    tp = len(flagged & truth)
    return {"flagged": len(flagged), "precision": tp / max(len(flagged), 1), "recall": tp / len(truth)}

def flag_suspicious():
    f = features(pd.read_csv(config.csv_path()))
    m = joblib.load(config.model_path())
    f["score"] = -m.score_samples(f[FEATS])
    out = f[m.predict(f[FEATS]) == -1].sort_values("score", ascending=False)
    return out.to_dict("records")
