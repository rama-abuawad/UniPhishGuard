import argparse
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
from sklearn.metrics import accuracy_score, average_precision_score, classification_report, confusion_matrix, roc_auc_score
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
                "split": (row.get("split") or "").strip().lower(),
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


def split_dataset(rows: list[dict[str, str]]) -> tuple[list[dict[str, str]], list[dict[str, str]], list[dict[str, str]], str]:
    declared = {row.get("split", "") for row in rows}
    expected = {"training", "validation", "testing"}
    if declared == expected:
        training = [row for row in rows if row["split"] == "training"]
        validation = [row for row in rows if row["split"] == "validation"]
        testing = [row for row in rows if row["split"] == "testing"]
        if not training or not validation or not testing:
            raise ValueError("Every declared dataset split must contain records.")
        for split_name, split in (("training", training), ("validation", validation), ("testing", testing)):
            if {row["label"] for row in split} != {"legitimate", "phishing"}:
                raise ValueError(f"The {split_name} split must contain both labels.")
        assert_no_group_leakage(training, validation, testing)
        return training, validation, testing, "declared_source_and_time_aware"
    if declared != {""}:
        raise ValueError("Dataset split values must be blank or exactly training/validation/testing.")
    training, validation, testing = grouped_split(rows)
    return training, validation, testing, "generated_stratified_group_split"


def assert_no_group_leakage(*splits: list[dict[str, str]]) -> None:
    group_sets = [{row["group"] for row in split} for split in splits]
    for left in range(len(group_sets)):
        for right in range(left + 1, len(group_sets)):
            overlap = group_sets[left] & group_sets[right]
            if overlap:
                raise ValueError(f"Group leakage detected across splits: {sorted(overlap)[:3]}")


def build_model(calibration_cv=3) -> Pipeline:
    return Pipeline([
        ("features", FeatureUnion([
            ("word", TfidfVectorizer(
                ngram_range=(1, 2), stop_words="english", min_df=2, max_df=0.995,
                max_features=60_000, strip_accents="unicode", sublinear_tf=True,
            )),
            ("char", TfidfVectorizer(
                analyzer="char_wb", ngram_range=(3, 5), min_df=2,
                max_features=80_000, strip_accents="unicode", sublinear_tf=True,
            )),
        ])),
        ("classifier", CalibratedClassifierCV(
            LogisticRegression(max_iter=2000, class_weight="balanced", C=2.0),
            method="sigmoid", cv=calibration_cv,
        )),
    ])


def threshold_candidates(probabilities: list[float], labels: list[str]) -> list[dict[str, float]]:
    actual = [label == "phishing" for label in labels]
    candidates = []
    for step in range(5, 96):
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
    report = classification_report(
        labels, predictions, labels=["legitimate", "phishing"], output_dict=True, zero_division=0,
    )
    matrix = confusion_matrix(labels, predictions, labels=["legitimate", "phishing"]).tolist()
    tn, fp = matrix[0]; fn, tp = matrix[1]
    binary = [label == "phishing" for label in labels]
    return {
        "accuracy": accuracy_score(labels, predictions),
        "precision": report["phishing"]["precision"],
        "recall": report["phishing"]["recall"],
        "f1": report["phishing"]["f1-score"],
        "classification_report": report,
        "confusion_matrix": matrix,
        "false_positive_rate": fp / (fp + tn) if fp + tn else 0.0,
        "false_negative_rate": fn / (fn + tp) if fn + tp else 0.0,
        "false_positives": fp,
        "false_negatives": fn,
        "roc_auc": roc_auc_score(binary, scores) if len(set(binary)) == 2 else None,
        "pr_auc": average_precision_score(binary, scores) if len(set(binary)) == 2 else None,
        "phishing_test_messages": labels.count("phishing"),
        "legitimate_test_messages": labels.count("legitimate"),
    }


def split_summary(rows: list[dict[str, str]]) -> dict:
    return {
        "records": len(rows),
        "groups": len({row["group"] for row in rows}),
        "class_balance": dict(Counter(row["label"] for row in rows)),
        "sources": dict(sorted(Counter(row["source"] for row in rows).items())),
    }


def git_commit() -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def metrics_by_field(model, rows: list[dict[str, str]], threshold: float, field: str) -> dict:
    result = {}
    for value in sorted({row[field] for row in rows}):
        subset = [row for row in rows if row[field] == value]
        result[value] = evaluate(subset, probabilities(model, subset), threshold)
    return result


def train(
    dataset_path: Path = DATASET_PATH,
    model_path: Path = MODEL_PATH,
    metrics_path: Path = METRICS_PATH,
    integrity_path: Path = INTEGRITY_PATH,
) -> dict:
    model_staging = model_path.with_suffix(model_path.suffix + ".tmp")
    metrics_staging = metrics_path.with_suffix(metrics_path.suffix + ".tmp")
    integrity_staging = integrity_path.with_suffix(integrity_path.suffix + ".tmp")
    raw_rows = load_dataset(dataset_path)
    rows, exact_duplicates, near_duplicate_groups = dedupe_and_group(raw_rows)
    train_rows, validation_rows, test_rows, split_strategy = split_dataset(rows)
    calibration_splitter = StratifiedGroupKFold(n_splits=3, shuffle=True, random_state=RANDOM_STATE + 2)
    calibration_cv = list(calibration_splitter.split(
        train_rows,
        [row["label"] for row in train_rows],
        [row["group"] for row in train_rows],
    ))
    model = build_model(calibration_cv)
    model.fit([row["text"] for row in train_rows], [row["label"] for row in train_rows])
    validation_scores = probabilities(model, validation_rows)
    threshold, candidates = choose_threshold(validation_scores, [row["label"] for row in validation_rows])
    test_metrics = evaluate(test_rows, probabilities(model, test_rows), threshold)
    model_path.parent.mkdir(parents=True, exist_ok=True)
    metrics_path.parent.mkdir(parents=True, exist_ok=True)
    integrity_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, model_staging)
    model_sha = sha256_file(model_staging)
    dataset_sha = sha256_file(dataset_path)
    metrics = {
        "evaluation_type": "Internal grouped holdout evaluation",
        "warning": "Internal evaluation results may not represent real-world university email performance. External validation is required before production use.",
        "model_name": "TF-IDF word+character n-grams with calibrated Logistic Regression",
        "model_version": "3.0.0", "training_timestamp": datetime.now(UTC).isoformat(),
        "phishing_threshold": threshold, "threshold_selection_policy": THRESHOLD_SELECTION_POLICY,
        "minimum_recall_target": MINIMUM_PHISHING_RECALL, "threshold_candidates": candidates,
        "original_dataset_size": len(raw_rows), "dataset_size": len(rows), "dataset_class_balance": dict(Counter(row["label"] for row in rows)),
        "exact_duplicates_removed": exact_duplicates, "near_duplicate_groups_detected": near_duplicate_groups,
        "number_of_groups": len({row["group"] for row in rows}),
        "split_strategy": split_strategy,
        "splits": {"training": split_summary(train_rows), "validation": split_summary(validation_rows), "testing": split_summary(test_rows)},
        "group_leakage_check": "passed", "test_metrics": test_metrics,
        "results_by_source": metrics_by_field(model, test_rows, threshold, "source"),
        "results_by_synthetic_status": metrics_by_field(model, test_rows, threshold, "is_synthetic"),
        "dataset_sources": dict(sorted(Counter(row["source"] for row in rows).items())),
        "dataset_sha256": dataset_sha, "model_sha256": model_sha, "git_commit": git_commit(), "random_state": RANDOM_STATE,
        "word_ngram_range": [1, 2], "char_ngram_range": [3, 5], "class_weight": "balanced",
        "logistic_regression_c": 2.0, "calibration_method": "sigmoid", "calibration_folds": 3,
        "calibration_group_aware": True, "training_command": "python train_model.py",
        "language_support": "Primarily English; Arabic and mixed-language performance has not been evaluated.",
        "runtime": {"python": platform.python_version(), "scikit_learn": sklearn.__version__, "joblib": joblib.__version__},
    }
    canonical = json.dumps(metrics, indent=2) + "\n"
    metrics["metrics_sha256"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    metrics_staging.write_text(json.dumps(metrics, indent=2) + "\n", encoding="utf-8")
    integrity = {"algorithm": "sha256", "email_model.joblib": model_sha, "model_metrics.json": sha256_file(metrics_staging), "training_dataset.csv": dataset_sha}
    integrity_staging.write_text(json.dumps(integrity, indent=2) + "\n", encoding="utf-8")
    model_staging.replace(model_path)
    metrics_staging.replace(metrics_path)
    integrity_staging.replace(integrity_path)
    result = {"threshold": threshold, "splits": metrics["splits"], "test_metrics": test_metrics, "group_leakage_check": "passed"}
    print(json.dumps(result, indent=2))
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train and evaluate the UniPhishGuard email text model.")
    parser.add_argument("--dataset", type=Path, default=DATASET_PATH)
    parser.add_argument("--model-output", type=Path, default=MODEL_PATH)
    parser.add_argument("--metrics-output", type=Path, default=METRICS_PATH)
    parser.add_argument("--integrity-output", type=Path, default=INTEGRITY_PATH)
    arguments = parser.parse_args()
    train(arguments.dataset, arguments.model_output, arguments.metrics_output, arguments.integrity_output)
