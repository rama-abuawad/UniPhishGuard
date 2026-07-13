from pathlib import Path

import joblib
from .models import EmailAnalysisRequest


MODEL_PATH = Path(__file__).with_name("email_model.joblib")
_MODEL = None


def _load_model():
    global _MODEL
    if _MODEL is None:
        if not MODEL_PATH.exists():
            raise FileNotFoundError(
                    "Email AI model is missing. Run 'python train_model.py' in the backend folder."
            )
        _MODEL = joblib.load(MODEL_PATH)
    return _MODEL


def predict_email_risk(email: EmailAnalysisRequest) -> tuple[str, float]:
    model = _load_model()
    text = f"{email.subject} {email.body}"
    prediction = str(model.predict([text])[0])

    probabilities = model.predict_proba([text])[0]
    classes = list(model.classes_)
    confidence = float(probabilities[classes.index(prediction)])

    return prediction, round(confidence, 2)
