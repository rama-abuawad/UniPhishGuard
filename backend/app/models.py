from pydantic import BaseModel, Field


class EmailAddress(BaseModel):
    name: str | None = None
    email: str


class AttachmentInfo(BaseModel):
    name: str
    content_type: str | None = None
    size: int | None = Field(default=None, ge=0)


class EmailAnalysisRequest(BaseModel):
    subject: str = ""
    sender: EmailAddress
    reply_to: str | None = None
    body: str = ""
    headers: str = ""
    attachments: list[AttachmentInfo] = Field(default_factory=list)


class Indicator(BaseModel):
    code: str
    severity: str
    message: str


class EmailAnalysisResponse(BaseModel):
    verdict: str
    risk_score: int = Field(ge=0, le=100)
    ai_prediction: str
    ai_confidence: float = Field(ge=0, le=1)
    indicators: list[Indicator]
    recommended_actions: list[str]
