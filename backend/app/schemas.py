"""Pydantic schemas for the UniPhishGuard API and persistence layer."""

from pydantic import BaseModel, Field


class EmailAddress(BaseModel):
    name: str | None = None
    email: str


class AttachmentInfo(BaseModel):
    name: str
    content_type: str | None = None
    size: int | None = Field(default=None, ge=0)
    content_base64: str | None = None


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


class ScoreComponent(BaseModel):
    code: str
    label: str
    score: int = Field(ge=0, le=100)
    cap: int = Field(ge=0, le=100)


class EmailAnalysisResponse(BaseModel):
    scan_id: int | None = None
    scanned_at: str | None = None
    verdict: str
    risk_score: int = Field(ge=0, le=100)
    threat_level: ThreatLevel
    threat_categories: list[ThreatCategory] = Field(default_factory=list)
    ai_prediction: str
    ai_confidence: float = Field(ge=0, le=1)
    ai_evidence: list[str] = Field(default_factory=list)
    score_breakdown: list[ScoreComponent] = Field(default_factory=list)
    top_reasons: list[str] = Field(default_factory=list)
    url_count: int = 0
    url_reputation_checked: int = 0
    url_reputation_status: str = "not_configured"
    attachment_count: int = 0
    attachment_hashes: list[str] = Field(default_factory=list)
    decoded_qr_links: list[LinkInfo] = Field(default_factory=list)
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
