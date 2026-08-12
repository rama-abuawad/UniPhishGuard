import argparse
import json
from datetime import UTC, datetime
from pathlib import Path

from app.ai import _load_model
from train_model import METRICS_PATH, MODEL_PATH, evaluate, load_dataset, probabilities, sha256_file


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate the saved UniPhishGuard model without retraining it.")
    parser.add_argument("csv_path", type=Path)
    parser.add_argument("--output", type=Path, default=Path("external_evaluation_metrics.json"))
    args = parser.parse_args()
    rows = load_dataset(args.csv_path)
    metadata = json.loads(METRICS_PATH.read_text(encoding="utf-8"))
    model = _load_model()
    result = {
        "evaluation_type": "Independent external evaluation",
        "evaluated_at": datetime.now(UTC).isoformat(),
        "dataset_path": str(args.csv_path),
        "dataset_sha256": sha256_file(args.csv_path),
        "model_sha256": sha256_file(MODEL_PATH),
        "phishing_threshold": metadata["phishing_threshold"],
        "warning": "External results apply only to the supplied dataset and are not training results.",
        "metrics": evaluate(rows, probabilities(model, rows), metadata["phishing_threshold"]),
    }
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(f"Saved external evaluation to {args.output}")


if __name__ == "__main__":
    main()
