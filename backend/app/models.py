from pydantic import BaseModel, Field


class EmailAddress(BaseModel):
    name: str | None = None
    email: str


class AttachmentInfo(BaseModel):
    name: str
    content_type: str | None = None
    size: int | None = Field(default=None, ge=0)


class LinkInfo(BaseModel):
    text: str = ""
    href: str


class EmailAnalysisRequest(BaseModel):
    subject: str = ""
    sender: EmailAddress
    reply_to: str | None = None
    body: str = ""
    body_html: str | None = None
    headers: str = ""
    headers_status: str = Field(default="checked", pattern="^(checked|not_available|failed)$")
    links: list[LinkInfo] = Field(default_factory=list)
    attachments: list[AttachmentInfo] = Field(default_factory=list)


class Indicator(BaseModel):
    code: str
    severity: str
    message: str


class ThreatCategory(BaseModel):
    code: str
    label: str
    evidence_strength: str
    reason: str


class ThreatLevel(BaseModel):
    code: str
    label: str
    color: str
    score_floor: int = Field(ge=0, le=100)


class EmailAnalysisResponse(BaseModel):
    scan_id: int | None = None
    scanned_at: str | None = None
    verdict: str
    risk_score: int = Field(ge=0, le=100)
    threat_level: ThreatLevel
    threat_categories: list[ThreatCategory] = Field(default_factory=list)
    ai_prediction: str
    ai_confidence: float = Field(ge=0, le=1)
    url_count: int = 0
    attachment_count: int = 0
    indicators: list[Indicator]
    recommended_actions: list[str]


class HistoryItem(BaseModel):
    scan_id: int
    scanned_at: str
    subject: str
    sender: str
    verdict: str
    risk_score: int
    indicator_count: int
