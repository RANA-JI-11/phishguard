"""
Train the phishing-classification model.

USAGE:
    python -m app.ml.train_model --data path/to/dataset.csv

Your CSV needs two columns: `url` and `label` where label is 1 for phishing
and 0 for legitimate. Good public datasets to start with:
  - Kaggle "Phishing Site URLs" (https://www.kaggle.com/datasets/taruntiwarihp/phishing-site-urls)
  - UCI Phishing Websites Dataset
  - PhishTank (https://www.phishtank.com/) verified phishing feed + Alexa/Tranco top sites as legitimate examples

This script trains a RandomForest (best accuracy/interpretability trade-off
for this feature set per the literature survey), evaluates it, and saves
`phishing_model.joblib` next to this file. predictor.py loads that file.
"""
import argparse
import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, roc_auc_score

from app.ml.feature_extractor import extract_features, features_to_vector, FEATURE_NAMES

MODEL_PATH = "app/ml/phishing_model.joblib"


def build_dataset(csv_path: str):
    df = pd.read_csv(csv_path)
    df = df.dropna(subset=["url", "label"])
    rows = []
    for url in df["url"]:
        result = extract_features(str(url))
        rows.append(features_to_vector(result["features"]))
    X = pd.DataFrame(rows, columns=FEATURE_NAMES)
    y = df["label"].astype(int).values
    return X, y


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", required=True, help="CSV with columns: url,label")
    parser.add_argument("--out", default=MODEL_PATH)
    args = parser.parse_args()

    print("Extracting features...")
    X, y = build_dataset(args.data)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print("Training RandomForestClassifier...")
    clf = RandomForestClassifier(
        n_estimators=300, max_depth=None, min_samples_leaf=2,
        class_weight="balanced", n_jobs=-1, random_state=42,
    )
    clf.fit(X_train, y_train)

    preds = clf.predict(X_test)
    probs = clf.predict_proba(X_test)[:, 1]
    print(classification_report(y_test, preds, target_names=["legitimate", "phishing"]))
    print("ROC-AUC:", roc_auc_score(y_test, probs))

    joblib.dump({"model": clf, "feature_names": FEATURE_NAMES}, args.out)
    print(f"Saved trained model to {args.out}")


if __name__ == "__main__":
    main()
