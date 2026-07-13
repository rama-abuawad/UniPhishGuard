from .models import EmailAnalysisRequest


PHISHING_KEYWORDS = {
    "urgent",
    "verify",
    "password",
    "suspended",
    "limited",
    "click",
    "login",
    "account",
    "payment",
    "invoice",
}


def predict_email_risk(email: EmailAnalysisRequest) -> tuple[str, float]:
    """Temporary keyword-based stand-in for the future trained model."""
    text = f"{email.subject} {email.body}".lower()
    hits = sum(1 for keyword in PHISHING_KEYWORDS if keyword in text)

    if hits >= 4:
        return "phishing", 0.78
    if hits >= 2:
        return "phishing", 0.62
    return "legitimate", 0.58
