import csv
import json
from pathlib import Path

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.pipeline import FeatureUnion
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline


ROOT = Path(__file__).resolve().parent
DATASET_PATH = ROOT / "data" / "training_emails.csv"
KD_DATASET_PATH = ROOT / "data" / "phishing_legit_dataset_KD_10000.csv"
MODEL_PATH = ROOT / "app" / "email_model.joblib"
METRICS_PATH = ROOT / "app" / "model_metrics.json"


def load_dataset() -> tuple[list[str], list[str]]:
    texts: list[str] = []
    labels: list[str] = []

    with DATASET_PATH.open(newline="", encoding="utf-8") as file:
        reader = csv.DictReader(file)
        for row in reader:
            labels.append(row["label"])
            texts.append(f"{row['subject']} {row['body']}")

    # Extra real-style dataset: 0 = legitimate, 1 = phishing.
    with KD_DATASET_PATH.open(newline="", encoding="utf-8-sig") as file:
        reader = csv.DictReader(file)
        for row in reader:
            label = "phishing" if row["label"].strip() == "1" else "legitimate"
            labels.append(label)
            texts.append(row["text"])

    return texts, labels


def train() -> None:
    texts, labels = load_dataset()
    train_texts, test_texts, train_labels, test_labels = train_test_split(
        texts,
        labels,
        test_size=0.25,
        random_state=42,
        stratify=labels,
    )
    model = Pipeline(
        [
            (
                "features",
                FeatureUnion(
                    [
                        ("word", TfidfVectorizer(ngram_range=(1, 2), stop_words="english")),
                        ("char", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5))),
                    ]
                ),
            ),
            ("classifier", LogisticRegression(max_iter=1000, class_weight="balanced")),
        ]
    )
    model.fit(train_texts, train_labels)
    predictions = model.predict(test_texts)
    report = classification_report(test_labels, predictions, output_dict=True, zero_division=0)
    matrix = confusion_matrix(test_labels, predictions, labels=["legitimate", "phishing"]).tolist()

    metrics = {
        "dataset_size": len(texts),
        "sources": {
            "generated_university_examples": str(DATASET_PATH.relative_to(ROOT)),
            "kd_10000_dataset": str(KD_DATASET_PATH.relative_to(ROOT)),
        },
        "train_size": len(train_texts),
        "test_size": len(test_texts),
        "labels": ["legitimate", "phishing"],
        "classification_report": report,
        "confusion_matrix": matrix,
    }

    joblib.dump(model, MODEL_PATH)
    METRICS_PATH.write_text(json.dumps(metrics, indent=2), encoding="utf-8")

    print(f"Saved model to {MODEL_PATH}")
    print(f"Saved metrics to {METRICS_PATH}")
    print(classification_report(test_labels, predictions, zero_division=0))


if __name__ == "__main__":
    train()
