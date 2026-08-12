from pathlib import Path
import hashlib
import json
import logging
import os
import re

import joblib
import sklearn
from .schemas import EmailAnalysisRequest
from .html_text import visible_html_text


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
URL_PATTERN = re.compile(r"(?:https?://|www\.)[^\s<>\"']+", re.IGNORECASE)
EMAIL_PATTERN = re.compile(r"\b[\w.+-]+@[\w.-]+\.[a-z]{2,}\b", re.IGNORECASE)
IP_PATTERN = re.compile(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)")


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
    """Return the strongest active TF-IDF contributions toward phishing."""
    try:
        model = _load_model()
        text = _model_text(email)
        features = model.named_steps["features"]
        classifier = model.named_steps["classifier"]
        vector = features.transform([text])
        names = features.get_feature_names_out()
        calibrated = getattr(classifier, "calibrated_classifiers_", [])
        coefficient_rows = [item.estimator.coef_[0] for item in calibrated]
        if not coefficient_rows:
            return []
        coefficients = sum(coefficient_rows) / len(coefficient_rows)
        contributions = vector.multiply(coefficients).tocoo()
        ranked = sorted(
            ((float(value), str(names[column])) for column, value in zip(contributions.col, contributions.data) if value > 0),
            reverse=True,
        )
        word_ranked = [(value, name.split("__", 1)[-1]) for value, name in ranked if name.startswith("word__")]
        char_ranked = [(value, name.split("__", 1)[-1]) for value, name in ranked if name.startswith("char__")]
        result: list[str] = []
        for value, feature in word_ranked + char_ranked:
            if feature not in result:
                result.append(feature)
            if len(result) == 5:
                break
        return result
    except (AttributeError, KeyError, TypeError, ValueError):
        LOGGER.warning("Model feature contributions could not be generated.")
        return []


def _model_text(email: EmailAnalysisRequest) -> str:
    plain = " ".join(email.body.split())
    visible_html = visible_html_text(email.body_html or "")
    body_parts = [plain]
    if visible_html and visible_html.lower() not in plain.lower() and plain.lower() not in visible_html.lower():
        body_parts.append(visible_html)
    links = " ".join(f"{link.text} {(link.href.split('/')[2] if '://' in link.href else link.href)}" for link in email.links)
    text = f"{email.subject} {' '.join(body_parts)} {links}".lower()
    # Outlook/Exchange may inject generic external-sender warnings. They describe
    # the organization boundary, not the sender's intent, so exclude them from ML.
    for phrase in (
        "external email: this email originated from outside the organization",
        "do not click links, provide information or open attachments unless you can confirm the sender",
        "this sender is from outside your organization",
        "you don't often get email from",
    ):
        text = text.replace(phrase, " ")
    # The attributed training dataset defangs active indicators. Apply the same
    # transformation at inference time so a benign URL or address cannot create
    # an out-of-distribution text pattern. URL/domain risk is handled by rules.
    text = URL_PATTERN.sub(" URL ", text)
    text = EMAIL_PATTERN.sub(" EMAIL ", text)
    text = IP_PATTERN.sub(" IP_ADDRESS ", text)
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
        expected_model = integrity["email_model.joblib"]
        expected_metrics = integrity["model_metrics.json"]
    except (OSError, KeyError, json.JSONDecodeError) as error:
        if allow_override:
            LOGGER.warning("Model integrity data is missing; development override is active.")
            return
        LOGGER.error("Model integrity verification failed: integrity data is missing or invalid.")
        raise RuntimeError("Model integrity data is missing or invalid.") from error
    if _sha256(MODEL_PATH) != expected_model:
        LOGGER.error("Model integrity verification failed: checksum mismatch.")
        raise RuntimeError("Model checksum does not match the trusted training artifact.")
    if not METRICS_PATH.exists() or _sha256(METRICS_PATH) != expected_metrics:
        LOGGER.error("Model metrics integrity verification failed: checksum mismatch.")
        raise RuntimeError("Model metrics checksum does not match the trusted training artifact.")


def _model_threshold() -> float:
    if not METRICS_PATH.exists():
        return 0.5
    try:
        metadata = json.loads(METRICS_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return 0.5
    return float(metadata.get("phishing_threshold", 0.5))


def model_threshold() -> float:
    """Expose the verified model decision threshold for API transparency."""
    _verify_model_integrity()
    return _model_threshold()
