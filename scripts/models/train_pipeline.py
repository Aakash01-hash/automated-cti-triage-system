import json
import os
import sys
from datetime import datetime, UTC

import joblib
import pandas as pd
import sklearn
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline


PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DATA_PATH = os.path.join(PROJECT_ROOT, "data", "processed", "final_cti_dataset.csv")
MODEL_PATH = os.path.join(PROJECT_ROOT, "models", "cti_pipeline.pkl")
METRICS_PATH = os.path.join(PROJECT_ROOT, "models", "cti_pipeline_metrics.json")


def load_dataset():
    df = pd.read_csv(DATA_PATH)
    df = df.dropna(subset=["text", "label"])
    df["text"] = df["text"].astype(str).str.strip()
    df["label"] = df["label"].astype(str).str.upper().str.strip()
    df = df[df["text"] != ""]
    df = df[df["label"].isin(["HIGH", "MEDIUM", "LOW"])]

    duplicate_count = int(df.duplicated(subset=["text", "label"]).sum())
    deduped = df.drop_duplicates(subset=["text", "label"])
    deduped_counts = deduped["label"].value_counts()
    if len(deduped_counts) == 3 and int(deduped_counts.min()) >= 1000:
        df = deduped
        retained_duplicates = 0
        print(f"Loaded {len(df):,} unique labelled rows after removing {duplicate_count:,} duplicates.")
    else:
        retained_duplicates = duplicate_count
        print(f"Loaded {len(df):,} labelled rows.")
        print(f"Exact duplicate text/label rows retained for class balance: {duplicate_count:,}")

    df.attrs["duplicate_text_label_rows_retained"] = retained_duplicates
    print(df["label"].value_counts().to_string())
    return df


def build_pipeline():
    return Pipeline(
        steps=[
            (
                "tfidf",
                TfidfVectorizer(
                    lowercase=True,
                    strip_accents="unicode",
                    ngram_range=(1, 2),
                    min_df=2,
                    max_features=50000,
                    sublinear_tf=True,
                ),
            ),
            (
                "classifier",
                LogisticRegression(
                    max_iter=2000,
                    class_weight="balanced",
                    solver="lbfgs",
                    random_state=42,
                ),
            ),
        ]
    )


def train():
    df = load_dataset()
    x_train, x_test, y_train, y_test = train_test_split(
        df["text"],
        df["label"],
        test_size=0.2,
        random_state=42,
        stratify=df["label"],
    )

    pipeline = build_pipeline()
    print("Training TF-IDF + Logistic Regression CTI classifier...")
    pipeline.fit(x_train, y_train)

    y_pred = pipeline.predict(x_test)
    labels = ["HIGH", "MEDIUM", "LOW"]
    report = classification_report(y_test, y_pred, labels=labels, output_dict=True)
    matrix = confusion_matrix(y_test, y_pred, labels=labels).tolist()

    metrics = {
        "model_name": "cti_pipeline",
        "model_path": MODEL_PATH,
        "trained_at_utc": datetime.now(UTC).isoformat(),
        "sklearn_version": sklearn.__version__,
        "dataset_path": DATA_PATH,
        "rows_after_cleaning": int(len(df)),
        "duplicate_text_label_rows_retained": int(df.attrs.get("duplicate_text_label_rows_retained", 0)),
        "labels": labels,
        "pipeline": {
            "vectorizer": "TfidfVectorizer",
            "classifier": "LogisticRegression",
            "ngram_range": [1, 2],
            "max_features": 50000,
        },
        "classification_report": report,
        "confusion_matrix": {
            "labels": labels,
            "matrix": matrix,
        },
    }

    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    joblib.dump(pipeline, MODEL_PATH)
    with open(METRICS_PATH, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)

    print("\nEvaluation:")
    print(classification_report(y_test, y_pred, labels=labels))
    print(f"Saved model to {MODEL_PATH}")
    print(f"Saved metrics to {METRICS_PATH}")


if __name__ == "__main__":
    sys.exit(train())
