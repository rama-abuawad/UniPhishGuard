from pathlib import Path
import json
import os

import joblib
import sklearn
from .models import EmailAnalysisRequest


MODEL_PATH = Path(__file__).with_name("email_model.joblib")
METRICS_PATH = Path(__file__).with_name("model_metrics.json")
MAX_MODEL_TEXT = 80_000
_MODEL = None


def _load_model():
    global _MODEL
    if _MODEL is None:
        if not MODEL_PATH.exists():
            raise FileNotFoundError(
                    "Email AI model is missing. Run 'python train_model.py' in the backend folder."
            )
        _check_model_metadata()
        _MODEL = joblib.load(MODEL_PATH)
    return _MODEL


def predict_email_risk(email: EmailAnalysisRequest) -> tuple[str, float]:
    model = _load_model()
    links = " ".join(f"{link.text} {link.href}" for link in email.links)
    text = f"{email.subject} {email.body} {email.body_html or ''} {links}"[:MAX_MODEL_TEXT]
    prediction = str(model.predict([text])[0])

    probabilities = model.predict_proba([text])[0]
    classes = list(model.classes_)
    confidence = float(probabilities[classes.index(prediction)])

    return prediction, round(confidence, 2)


def _check_model_metadata() -> None:
    if not METRICS_PATH.exists():
        return
    try:
        metadata = json.loads(METRICS_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return

    trained_version = metadata.get("runtime", {}).get("scikit_learn")
    if trained_version and trained_version != sklearn.__version__ and os.getenv("STRICT_MODEL_VERSION") == "true":
        raise RuntimeError(
            f"Model was trained with scikit-learn {trained_version}, but runtime is {sklearn.__version__}."
        )
