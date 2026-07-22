import csv
import hashlib
import json
import platform
import re
import subprocess
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

import joblib
import sklearn
from sklearn.calibration import CalibratedClassifierCV
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, classification_report, confusion_matrix, roc_auc_score
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.pipeline import FeatureUnion, Pipeline


ROOT = Path(__file__).resolve().parent
DATASET_PATH = ROOT / "data" / "training_dataset.csv"
MODEL_PATH = ROOT / "app" / "email_model.joblib"
METRICS_PATH = ROOT / "app" / "model_metrics.json"
INTEGRITY_PATH = ROOT / "app" / "model_integrity.json"
RANDOM_STATE = 42
MINIMUM_PHISHING_RECALL = 0.95
THRESHOLD_SELECTION_POLICY = "minimum_phishing_recall_then_minimum_false_positive_rate"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def normalize_text(text: str) -> str:
    text = text.lower()
    text = re.sub(r"https?://\S+|www\.\S+", " URL ", text)
    text = re.sub(r"\b[\w.+-]+@[\w.-]+\.[a-z]{2,}\b", " EMAIL ", text)
    text = re.sub(r"[$£€₹]\s?\d[\d,.]*|\b\d[\d,.]*\s?(?:usd|aed|gbp|eur|btc)\b", " AMOUNT ", text)
    text = re.sub(r"\b(?:monday|tuesday|wednesday|thursday|friday|saturday|sunday)\b", " DAY ", text)
    text = re.sub(r"\b(?:january|february|march|april|may|june|july|august|september|october|november|december)\b", " MONTH ", text)
    text = re.sub(r"\b\d+(?:st|nd|rd|th)?\b", " NUMBER ", text)
    text = re.sub(r"\b(?:dear (?:student|user|customer)|hello|hi there|attention|notice|account holder)\b", " GREETING ", text)
    return " ".join(re.sub(r"[^a-z_ ]", " ", text).split())


def template_fingerprint(text: str, explicit_template_id: str = "") -> str:
    if explicit_template_id.strip():
        return f"template:{explicit_template_id.strip().lower()}"
    normalized = normalize_text(text)
    tokens = normalized.split()
    # Dropping very short tokens and hashing the normalized template makes the
    # grouping deterministic without retaining another copy of message text.
    meaningful = [token for token in tokens if len(token) > 2 and token != "greeting"]
    # Template datasets usually vary values and trailing clauses while retaining
    # a stable opening. Grouping on the first twelve normalized meaningful words
    # deliberately favors leakage prevention over maximizing the training split.
    stable = " ".join(meaningful[:12])
    return hashlib.sha256(stable.encode("utf-8")).hexdigest()[:20]


def load_dataset(path: Path = DATASET_PATH) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8-sig") as file:
        reader = csv.DictReader(file)
        if not reader.fieldnames or not {"label", "text"}.issubset(reader.fieldnames):
            raise ValueError("Dataset must contain label and text columns.")
        rows = []
        for row in reader:
            label = row["label"].strip().lower()
            text = row["text"].strip()
            if label not in {"legitimate", "phishing"} or not text:
                raise ValueError("Each dataset row needs non-empty text and a legitimate/phishing label.")
            rows.append({
                "label": label,
                "text": text,
                "source": (row.get("source") or "unknown").strip() or "unknown",
                "template_id": (row.get("template_id") or "").strip(),
                "is_synthetic": (row.get("is_synthetic") or "unknown").strip().lower() or "unknown",
            })
    return rows


def dedupe_and_group(rows: list[dict[str, str]]) -> tuple[list[dict[str, str]], int, int]:
    unique: list[dict[str, str]] = []
    seen: set[str] = set()
    for row in rows:
        exact = " ".join(row["text"].lower().split())
        if exact in seen:
            continue
        seen.add(exact)
        item = dict(row)
        item["group"] = f'{row["label"]}:{template_fingerprint(row["text"], row["template_id"])}'
        unique.append(item)
    group_sizes = Counter(row["group"] for row in unique)
    near_duplicate_groups = sum(size > 1 for size in group_sizes.values())
    return unique, len(rows) - len(unique), near_duplicate_groups


def grouped_split(rows: list[dict[str, str]]) -> tuple[list[dict[str, str]], list[dict[str, str]], list[dict[str, str]]]:
    labels = [row["label"] for row in rows]
    groups = [row["group"] for row in rows]
    outer = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=RANDOM_STATE)
    train_validation_idx, test_idx = next(outer.split(rows, labels, groups))
    train_validation = [rows[index] for index in train_validation_idx]
    tv_labels = [row["label"] for row in train_validation]
    tv_groups = [row["group"] for row in train_validation]
    inner = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=RANDOM_STATE + 1)
    train_idx, validation_idx = next(inner.split(train_validation, tv_labels, tv_groups))
    train = [train_validation[index] for index in train_idx]
    validation = [train_validation[index] for index in validation_idx]
    test = [rows[index] for index in test_idx]
    assert_no_group_leakage(train, validation, test)
    return train, validation, test


def assert_no_group_leakage(*splits: list[dict[str, str]]) -> None:
    group_sets = [{row["group"] for row in split} for split in splits]
    for left in range(len(group_sets)):
        for right in range(left + 1, len(group_sets)):
            overlap = group_sets[left] & group_sets[right]
            if overlap:
                raise ValueError(f"Group leakage detected across splits: {sorted(overlap)[:3]}")


def build_model() -> Pipeline:
    return Pipeline([
        ("features", FeatureUnion([
            ("word", TfidfVectorizer(ngram_range=(1, 2), stop_words="english")),
            ("char", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5))),
        ])),
        ("classifier", CalibratedClassifierCV(
            LogisticRegression(max_iter=1000, class_weight="balanced"), method="sigmoid", cv=3,
        )),
    ])


def threshold_candidates(probabilities: list[float], labels: list[str]) -> list[dict[str, float]]:
    actual = [label == "phishing" for label in labels]
    candidates = []
    for step in range(20, 81):
        threshold = step / 100
        predicted = [value >= threshold for value in probabilities]
        tp = sum(a and p for a, p in zip(actual, predicted)); fp = sum(not a and p for a, p in zip(actual, predicted))
        fn = sum(a and not p for a, p in zip(actual, predicted)); tn = sum(not a and not p for a, p in zip(actual, predicted))
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        candidates.append({
            "threshold": threshold, "precision": precision, "recall": recall,
            "f1": 2 * precision * recall / (precision + recall) if precision + recall else 0.0,
            "false_positive_rate": fp / (fp + tn) if fp + tn else 0.0,
            "false_negative_rate": fn / (fn + tp) if fn + tp else 0.0,
        })
    return candidates


def choose_threshold(probabilities: list[float], labels: list[str], minimum_recall: float = MINIMUM_PHISHING_RECALL):
    candidates = threshold_candidates(probabilities, labels)
    eligible = [candidate for candidate in candidates if candidate["recall"] >= minimum_recall]
    pool = eligible or candidates
    selected = min(pool, key=lambda item: (item["false_positive_rate"], -item["recall"], -item["f1"]))
    return selected["threshold"], candidates


def probabilities(model, rows: list[dict[str, str]]) -> list[float]:
    values = model.predict_proba([row["text"] for row in rows])
    index = list(model.classes_).index("phishing")
    return [float(value[index]) for value in values]


def evaluate(rows: list[dict[str, str]], scores: list[float], threshold: float) -> dict:
    labels = [row["label"] for row in rows]
    predictions = ["phishing" if score >= threshold else "legitimate" for score in scores]
    report = classification_report(labels, predictions, output_dict=True, zero_division=0)
    matrix = confusion_matrix(labels, predictions, labels=["legitimate", "phishing"]).tolist()
    tn, fp = matrix[0]; fn, tp = matrix[1]
    binary = [label == "phishing" for label in labels]
    return {
        "accuracy": report["accuracy"],
        "precision": report["phishing"]["precision"],
        "recall": report["phishing"]["recall"],
        "f1": report["phishing"]["f1-score"],
        "classification_report": report,
        "confusion_matrix": matrix,
        "false_positive_rate": fp / (fp + tn) if fp + tn else 0.0,
        "false_negative_rate": fn / (fn + tp) if fn + tp else 0.0,
        "roc_auc": roc_auc_score(binary, scores),
        "pr_auc": average_precision_score(binary, scores),
        "phishing_test_messages": labels.count("phishing"),
        "legitimate_test_messages": labels.count("legitimate"),
    }


def split_summary(rows: list[dict[str, str]]) -> dict:
    return {"records": len(rows), "groups": len({row["group"] for row in rows}), "class_balance": dict(Counter(row["label"] for row in rows))}


def git_commit() -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def train() -> None:
    raw_rows = load_dataset()
    rows, exact_duplicates, near_duplicate_groups = dedupe_and_group(raw_rows)
    train_rows, validation_rows, test_rows = grouped_split(rows)
    model = build_model()
    model.fit([row["text"] for row in train_rows], [row["label"] for row in train_rows])
    validation_scores = probabilities(model, validation_rows)
    threshold, candidates = choose_threshold(validation_scores, [row["label"] for row in validation_rows])
    test_metrics = evaluate(test_rows, probabilities(model, test_rows), threshold)
    joblib.dump(model, MODEL_PATH)
    model_sha = sha256_file(MODEL_PATH)
    dataset_sha = sha256_file(DATASET_PATH)
    metrics = {
        "evaluation_type": "internal_grouped_holdout",
        "warning": "Internal evaluation results may not represent real-world university email performance. External validation is required before production use.",
        "model_name": "TF-IDF word+character n-grams with calibrated Logistic Regression",
        "model_version": "2.0.0", "training_timestamp": datetime.now(UTC).isoformat(),
        "phishing_threshold": threshold, "threshold_selection_policy": THRESHOLD_SELECTION_POLICY,
        "minimum_recall_target": MINIMUM_PHISHING_RECALL, "threshold_candidates": candidates,
        "original_dataset_size": len(raw_rows), "dataset_size": len(rows), "dataset_class_balance": dict(Counter(row["label"] for row in rows)),
        "exact_duplicates_removed": exact_duplicates, "near_duplicate_groups_detected": near_duplicate_groups,
        "number_of_groups": len({row["group"] for row in rows}),
        "splits": {"training": split_summary(train_rows), "validation": split_summary(validation_rows), "testing": split_summary(test_rows)},
        "group_leakage_check": "passed", "test_metrics": test_metrics,
        "results_by_source": "unavailable: source metadata is not verified in the consolidated dataset",
        "results_by_synthetic_status": "unavailable: synthetic metadata is incomplete",
        "dataset_sha256": dataset_sha, "model_sha256": model_sha, "git_commit": git_commit(), "random_state": RANDOM_STATE,
        "word_ngram_range": [1, 2], "char_ngram_range": [3, 5], "class_weight": "balanced",
        "calibration_method": "sigmoid", "calibration_folds": 3, "training_command": "python train_model.py",
        "language_support": "Primarily English; Arabic and mixed-language performance has not been evaluated.",
        "runtime": {"python": platform.python_version(), "scikit_learn": sklearn.__version__, "joblib": joblib.__version__},
    }
    canonical = json.dumps(metrics, indent=2) + "\n"
    metrics["metrics_sha256"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    METRICS_PATH.write_text(json.dumps(metrics, indent=2) + "\n", encoding="utf-8")
    integrity = {"algorithm": "sha256", "email_model.joblib": model_sha, "model_metrics.json": sha256_file(METRICS_PATH), "training_dataset.csv": dataset_sha}
    INTEGRITY_PATH.write_text(json.dumps(integrity, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"threshold": threshold, "splits": metrics["splits"], "test_metrics": test_metrics, "group_leakage_check": "passed"}, indent=2))


if __name__ == "__main__":
    train()
