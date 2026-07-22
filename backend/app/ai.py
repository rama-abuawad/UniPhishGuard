from pathlib import Path
import hashlib
import json
import logging
import os

import joblib
import sklearn
from .schemas import EmailAnalysisRequest


MODEL_PATH = Path(__file__).with_name("email_model.joblib")
METRICS_PATH = Path(__file__).with_name("model_metrics.json")
INTEGRITY_PATH = Path(__file__).with_name("model_integrity.json")
MAX_MODEL_TEXT = 80_000
_MODEL = None
LOGGER = logging.getLogger(__name__)
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
        _verify_model_integrity()
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
    text = f"{email.subject} {email.body} {email.body_html or ''} {links}".lower()
    # Outlook/Exchange may inject generic external-sender warnings. They describe
    # the organization boundary, not the sender's intent, so exclude them from ML.
    for phrase in (
        "external email: this email originated from outside the organization",
        "do not click links, provide information or open attachments unless you can confirm the sender",
        "this sender is from outside your organization",
        "you don't often get email from",
    ):
        text = text.replace(phrase, " ")
    return " ".join(text.split())[:MAX_MODEL_TEXT]


def _check_model_metadata() -> None:
    if not METRICS_PATH.exists():
        return
    try:
        metadata = json.loads(METRICS_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return

    trained_version = metadata.get("runtime", {}).get("scikit_learn")
    app_env = os.getenv("APP_ENV", "development").lower()
    strict = app_env == "production" or os.getenv("STRICT_MODEL_VERSION", "false").lower() == "true"
    override = os.getenv("ALLOW_MODEL_VERSION_MISMATCH", "false").lower() == "true"
    if trained_version and trained_version != sklearn.__version__ and strict and not override:
        raise RuntimeError(
            f"Model was trained with scikit-learn {trained_version}, but runtime is {sklearn.__version__}."
        )
    if trained_version and trained_version != sklearn.__version__:
        LOGGER.warning("Model/runtime scikit-learn versions differ: trained=%s runtime=%s", trained_version, sklearn.__version__)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _verify_model_integrity() -> None:
    allow_override = (
        os.getenv("APP_ENV", "development").lower() == "development"
        and os.getenv("ALLOW_UNVERIFIED_MODEL", "false").lower() == "true"
    )
    try:
        integrity = json.loads(INTEGRITY_PATH.read_text(encoding="utf-8"))
        expected = integrity["email_model.joblib"]
    except (OSError, KeyError, json.JSONDecodeError) as error:
        if allow_override:
            LOGGER.warning("Model integrity data is missing; development override is active.")
            return
        LOGGER.error("Model integrity verification failed: integrity data is missing or invalid.")
        raise RuntimeError("Model integrity data is missing or invalid.") from error
    actual = _sha256(MODEL_PATH)
    if actual != expected:
        LOGGER.error("Model integrity verification failed: checksum mismatch.")
        raise RuntimeError("Model checksum does not match the trusted training artifact.")


def _model_threshold() -> float:
    if not METRICS_PATH.exists():
        return 0.5
    try:
        metadata = json.loads(METRICS_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return 0.5
    return float(metadata.get("phishing_threshold", 0.5))
