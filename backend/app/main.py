from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .analyzer import analyze_email
from .models import EmailAnalysisRequest, EmailAnalysisResponse

app = FastAPI(
    title="UniPhishGuard API",
    description="Email phishing analysis backend for the Outlook add-in.",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://localhost:3000",
        "https://127.0.0.1:3000",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=True,
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/analyze-email", response_model=EmailAnalysisResponse)
def analyze(email: EmailAnalysisRequest) -> EmailAnalysisResponse:
    return analyze_email(email)
