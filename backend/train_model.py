import csv
import json
import platform
from datetime import UTC, datetime
from pathlib import Path

import joblib
import sklearn
from sklearn.calibration import CalibratedClassifierCV
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import average_precision_score, classification_report, confusion_matrix, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import FeatureUnion
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline


ROOT = Path(__file__).resolve().parent
DATASET_PATH = ROOT / "data" / "training_dataset.csv"
MODEL_PATH = ROOT / "app" / "email_model.joblib"
METRICS_PATH = ROOT / "app" / "model_metrics.json"


def load_dataset() -> tuple[list[str], list[str]]:
    texts: list[str] = []
    labels: list[str] = []

    with DATASET_PATH.open(newline="", encoding="utf-8-sig") as file:
        reader = csv.DictReader(file)
        for row in reader:
            labels.append(row["label"].strip())
            texts.append(row["text"].strip())

    return texts, labels


def dedupe_dataset(texts: list[str], labels: list[str]) -> tuple[list[str], list[str], int]:
    seen: dict[str, str] = {}
    deduped_texts: list[str] = []
    deduped_labels: list[str] = []

    for text, label in zip(texts, labels):
        key = " ".join(text.lower().split())
        if key in seen:
            continue
        seen[key] = label
        deduped_texts.append(text)
        deduped_labels.append(label)

    return deduped_texts, deduped_labels, len(texts) - len(deduped_texts)


def train() -> None:
    texts, labels = load_dataset()
    raw_size = len(texts)
    texts, labels, duplicate_count = dedupe_dataset(texts, labels)
    train_texts, temp_texts, train_labels, temp_labels = train_test_split(
        texts,
        labels,
        test_size=0.30,
        random_state=42,
        stratify=labels,
    )
    validation_texts, test_texts, validation_labels, test_labels = train_test_split(
        temp_texts,
        temp_labels,
        test_size=0.50,
        random_state=42,
        stratify=temp_labels,
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
            (
                "classifier",
                CalibratedClassifierCV(
                    LogisticRegression(max_iter=1000, class_weight="balanced"),
                    method="sigmoid",
                    cv=3,
                ),
            ),
        ]
    )
    model.fit(train_texts, train_labels)
    threshold = choose_threshold(model, validation_texts, validation_labels)
    probabilities = model.predict_proba(test_texts)
    classes = list(model.classes_)
    phishing_index = classes.index("phishing")
    phishing_probabilities = [float(row[phishing_index]) for row in probabilities]
    predictions = ["phishing" if probability >= threshold else "legitimate" for probability in phishing_probabilities]
    report = classification_report(test_labels, predictions, output_dict=True, zero_division=0)
    matrix = confusion_matrix(test_labels, predictions, labels=["legitimate", "phishing"]).tolist()
    tn, fp = matrix[0]
    fn, tp = matrix[1]
    false_positive_rate = fp / (fp + tn) if fp + tn else 0
    false_negative_rate = fn / (fn + tp) if fn + tp else 0

    metrics = {
        "model_name": "TF-IDF word+character n-grams with calibrated Logistic Regression",
        "model_version": "1.1.0",
        "training_date": datetime.now(UTC).isoformat(),
        "phishing_threshold": threshold,
        "raw_dataset_size": raw_size,
        "dataset_size": len(texts),
        "exact_duplicates_removed": duplicate_count,
        "source": str(DATASET_PATH.relative_to(ROOT)),
        "train_size": len(train_texts),
        "validation_size": len(validation_texts),
        "test_size": len(test_texts),
        "labels": ["legitimate", "phishing"],
        "classification_report": report,
        "confusion_matrix": matrix,
        "false_positive_rate": false_positive_rate,
        "false_negative_rate": false_negative_rate,
        "roc_auc": roc_auc_score([1 if label == "phishing" else 0 for label in test_labels], phishing_probabilities),
        "pr_auc": average_precision_score([1 if label == "phishing" else 0 for label in test_labels], phishing_probabilities),
        "language_support": "English baseline. Arabic and mixed Arabic-English examples are not yet included.",
        "runtime": {
            "python": platform.python_version(),
            "scikit_learn": sklearn.__version__,
            "joblib": joblib.__version__,
        },
    }

    joblib.dump(model, MODEL_PATH)
    METRICS_PATH.write_text(json.dumps(metrics, indent=2), encoding="utf-8")

    print(f"Saved model to {MODEL_PATH}")
    print(f"Saved metrics to {METRICS_PATH}")
    print(classification_report(test_labels, predictions, zero_division=0))


def choose_threshold(model, validation_texts: list[str], validation_labels: list[str]) -> float:
    probabilities = model.predict_proba(validation_texts)
    classes = list(model.classes_)
    phishing_index = classes.index("phishing")
    y_true = [1 if label == "phishing" else 0 for label in validation_labels]
    best_threshold = 0.50
    best_score = -1.0

    for step in range(30, 76):
        threshold = step / 100
        predictions = [1 if row[phishing_index] >= threshold else 0 for row in probabilities]
        tp = sum(1 for actual, predicted in zip(y_true, predictions) if actual == 1 and predicted == 1)
        fp = sum(1 for actual, predicted in zip(y_true, predictions) if actual == 0 and predicted == 1)
        fn = sum(1 for actual, predicted in zip(y_true, predictions) if actual == 1 and predicted == 0)
        precision = tp / (tp + fp) if tp + fp else 0
        recall = tp / (tp + fn) if tp + fn else 0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0
        if f1 > best_score:
            best_score = f1
            best_threshold = threshold

    return best_threshold


if __name__ == "__main__":
    train()
