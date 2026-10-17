"""
SilkShield ML Training Script
==============================
Trains an XGBoost binary classifier on synthetic threat-intelligence data.

⚠ Training data is synthetic — designed to exercise the pipeline, NOT
  production-grade.  See evaluation.md for limitations.

Usage
-----
    python -m ml.train
"""

from __future__ import annotations

import os

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier

from ml.features import get_feature_names

MODEL_DIR = os.path.join(os.path.dirname(__file__), "model")
MODEL_PATH = os.path.join(MODEL_DIR, "xgboost_model.joblib")


# ---------- synthetic data ---------- #

def generate_synthetic_data(n: int = 2000, seed: int = 42) -> pd.DataFrame:
    rng = np.random.RandomState(seed)
    rows: list[list] = []

    half = n // 2
    for _ in range(half):
        # ---- malicious sample ----
        det = rng.randint(5, 50)
        total = rng.randint(60, 95)
        rows.append([
            det, total, det / total,
            rng.randint(-100, -10),                       # reputation
            rng.randint(0, 10),                           # related_count
            max(det - rng.randint(0, 5), 0),              # malicious_votes
            rng.randint(0, 5),                            # suspicious_votes
            rng.randint(10, 60),                          # domain_length
            rng.randint(0, 5),                            # subdomain_count
            rng.choice([0, 1], p=[0.7, 0.3]),             # has_ip_in_name
            rng.randint(0, 5),                            # suspicious_keywords
            rng.randint(20, 200),                         # url_length
            rng.choice([0, 1], p=[0.6, 0.4]),             # has_https
            rng.randint(0, 8),                            # path_depth
            rng.choice([0, 1], p=[0.4, 0.6]),             # has_query
            rng.choice([-1, 0], p=[0.4, 0.6]),            # asn_reputation
            rng.randint(1, 10),                           # dns_record_count
            rng.randint(0, 90),                           # domain_age_days
            1,                                            # label
        ])

        # ---- benign sample ----
        det_b = rng.randint(0, 3)
        total_b = rng.randint(60, 95)
        rows.append([
            det_b, total_b, det_b / total_b,
            rng.randint(0, 100),
            rng.randint(0, 3),
            det_b,
            rng.randint(0, 2),
            rng.randint(5, 25),
            rng.randint(0, 2),
            0,
            rng.randint(0, 1),
            rng.randint(10, 50),
            rng.choice([0, 1], p=[0.2, 0.8]),
            rng.randint(0, 3),
            rng.choice([0, 1], p=[0.7, 0.3]),
            0,
            rng.randint(5, 30),
            rng.randint(365, 10000),
            0,
        ])

    cols = get_feature_names() + ["label"]
    return pd.DataFrame(rows, columns=cols)


# ---------- training ---------- #

def train() -> None:
    sep = "=" * 60
    print(sep)
    print("  SilkShield ML Training")
    print(sep)

    # 1 — data
    print("\n[1/5] Generating synthetic training data ...")
    df = generate_synthetic_data(2000)
    print(f"  Samples : {len(df)}  (malicious={int((df['label']==1).sum())}, "
          f"benign={int((df['label']==0).sum())})")

    # 2 — split
    print("\n[2/5] Splitting data (80 / 20 stratified) ...")
    names = get_feature_names()
    X = df[names].values
    y = df["label"].values
    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y,
    )
    print(f"  Train : {len(X_tr)}   Test : {len(X_te)}")

    # 3 — train
    print("\n[3/5] Training XGBoost ...")
    model = XGBClassifier(
        n_estimators=100,
        max_depth=6,
        learning_rate=0.1,
        objective="binary:logistic",
        eval_metric="logloss",
        random_state=42,
    )
    model.fit(X_tr, y_tr, eval_set=[(X_te, y_te)], verbose=False)

    # 4 — evaluate
    print("\n[4/5] Evaluating ...")
    y_pred = model.predict(X_te)
    y_prob = model.predict_proba(X_te)[:, 1]

    acc  = accuracy_score(y_te, y_pred)
    prec = precision_score(y_te, y_pred)
    rec  = recall_score(y_te, y_pred)
    f1   = f1_score(y_te, y_pred)
    auc  = roc_auc_score(y_te, y_prob)
    cm   = confusion_matrix(y_te, y_pred)

    print(f"  Accuracy  : {acc:.4f}")
    print(f"  Precision : {prec:.4f}")
    print(f"  Recall    : {rec:.4f}")
    print(f"  F1        : {f1:.4f}")
    print(f"  ROC-AUC   : {auc:.4f}")
    print(f"\n  Confusion Matrix\n    TN={cm[0][0]}  FP={cm[0][1]}\n    FN={cm[1][0]}  TP={cm[1][1]}")
    print(f"\n{classification_report(y_te, y_pred, target_names=['Benign','Malicious'])}")

    imp = sorted(zip(names, model.feature_importances_), key=lambda x: -x[1])
    print("  Top features:")
    for name, val in imp[:10]:
        print(f"    {name:25s} {val:.4f}")

    # 5 — save
    print(f"\n[5/5] Saving model ...")
    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    print(f"  -> {MODEL_PATH}")

    # save evaluation report
    eval_path = os.path.join(os.path.dirname(__file__), "evaluation.md")
    with open(eval_path, "w", encoding="utf-8") as fh:
        fh.write("# SilkShield ML Evaluation\n\n")
        fh.write("## Dataset\n\n")
        fh.write("Synthetic data generated from realistic threat-intelligence patterns.\n\n")
        fh.write(f"- Total samples: {len(df)}\n")
        fh.write(f"- Train / Test: {len(X_tr)} / {len(X_te)} (80/20 stratified)\n\n")
        fh.write("## Results\n\n")
        fh.write("| Metric | Value |\n|--------|-------|\n")
        for label, val in [("Accuracy", acc), ("Precision", prec),
                           ("Recall", rec), ("F1", f1), ("ROC-AUC", auc)]:
            fh.write(f"| {label} | {val:.4f} |\n")
        fh.write("\n## Limitations\n\n")
        fh.write("- Training data is **synthetic**, not from real-world labelled datasets.\n")
        fh.write("- Model is a datathon prototype — **not production-grade**.\n")
        fh.write("- Feature coverage depends on threat-intelligence provider availability.\n")
    print(f"  -> {eval_path}")

    print(f"\n{sep}\n  Training complete!\n{sep}")


if __name__ == "__main__":
    train()
