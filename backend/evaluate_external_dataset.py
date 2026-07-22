import argparse
import csv
import json
from pathlib import Path

from sklearn.metrics import average_precision_score, classification_report, confusion_matrix, roc_auc_score

from app.ai import predict_email_risk
from app.schemas import EmailAnalysisRequest, EmailAddress


ROOT = Path(__file__).resolve().parent
OUTPUT_DIR = ROOT / "app" / "external_evaluations"


def load_rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8-sig") as file:
        return list(csv.DictReader(file))


def row_text(row: dict[str, str]) -> tuple[str, str]:
    if "text" in row:
        return row.get("subject", ""), row["text"]
    return row.get("subject", ""), row.get("body", "")


def normalize_label(value: str) -> str:
    value = str(value).strip().lower()
    if value in {"1", "phish", "phishing", "malicious", "bad"}:
        return "phishing"
    if value in {"0", "legit", "legitimate", "ham", "safe"}:
        return "legitimate"
    raise ValueError(f"Unknown label: {value}")


def evaluate(path: Path, label_column: str) -> dict:
    rows = load_rows(path)
    true_labels: list[str] = []
    predicted_labels: list[str] = []
    phishing_probabilities: list[float] = []

    for row in rows:
        subject, body = row_text(row)
        true_label = normalize_label(row[label_column])
        prediction, probability = predict_email_risk(
            EmailAnalysisRequest(
                subject=subject,
                sender=EmailAddress(email="external-dataset@example.com"),
                body=body,
            )
        )
        true_labels.append(true_label)
        predicted_labels.append(prediction if prediction in {"legitimate", "phishing"} else "legitimate")
        phishing_probabilities.append(probability)

    matrix = confusion_matrix(true_labels, predicted_labels, labels=["legitimate", "phishing"]).tolist()
    tn, fp = matrix[0]
    fn, tp = matrix[1]
    y_true = [1 if label == "phishing" else 0 for label in true_labels]

    return {
        "dataset": str(path),
        "sample_count": len(rows),
        "label_column": label_column,
        "classification_report": classification_report(true_labels, predicted_labels, output_dict=True, zero_division=0),
        "confusion_matrix": matrix,
        "false_positive_rate": fp / (fp + tn) if fp + tn else 0,
        "false_negative_rate": fn / (fn + tp) if fn + tp else 0,
        "roc_auc": roc_auc_score(y_true, phishing_probabilities) if len(set(y_true)) > 1 else None,
        "pr_auc": average_precision_score(y_true, phishing_probabilities) if len(set(y_true)) > 1 else None,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate UniPhishGuard on an independent external CSV dataset.")
    parser.add_argument("dataset", type=Path)
    parser.add_argument("--label-column", default="label")
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args()

    metrics = evaluate(args.dataset, args.label_column)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    output_path = args.output or OUTPUT_DIR / f"{args.dataset.stem}_metrics.json"
    output_path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    print(json.dumps(metrics, indent=2))
    print(f"Saved external evaluation to {output_path}")


if __name__ == "__main__":
    main()
