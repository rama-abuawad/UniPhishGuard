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
SUSPICIOUS_PHRASES = (
    "verify your account",
    "urgent action",
    "password expires",
    "account locked",
    "sign in",
    "login",
    "microsoft 365",
    "office 365",
    "update your account",
    "confirm your account",
    "download attachment",
    "enable macros",
)


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
    try:
        model = _load_model()
    except (FileNotFoundError, RuntimeError, ValueError):
        return "unavailable", 0.0

    text = _model_text(email)
    if not text.strip():
        return "legitimate", 0.5

    probabilities = model.predict_proba([text])[0]
    classes = list(model.classes_)
    phishing_probability = float(probabilities[classes.index("phishing")])
    threshold = _model_threshold()
    prediction = "phishing" if phishing_probability >= threshold else "legitimate"

    return prediction, round(phishing_probability, 2)


def explain_email_risk(email: EmailAnalysisRequest) -> list[str]:
    text = _model_text(email).lower()
    return [phrase for phrase in SUSPICIOUS_PHRASES if phrase in text][:5]


def _model_text(email: EmailAnalysisRequest) -> str:
    links = " ".join(f"{link.text} {link.href}" for link in email.links)
    return f"{email.subject} {email.body} {email.body_html or ''} {links}"[:MAX_MODEL_TEXT]


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


def _model_threshold() -> float:
    if not METRICS_PATH.exists():
        return 0.5
    try:
        metadata = json.loads(METRICS_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return 0.5
    return float(metadata.get("phishing_threshold", 0.5))
