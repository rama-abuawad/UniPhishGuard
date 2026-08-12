"""Pydantic schemas for the UniPhishGuard API and persistence layer."""

from pydantic import BaseModel, Field, field_validator

MAX_SUBJECT_LENGTH = 998
MAX_BODY_LENGTH = 200_000
MAX_HTML_LENGTH = 500_000
MAX_HEADERS_LENGTH = 100_000
MAX_LINKS = 100
MAX_ATTACHMENTS = 50
MAX_URL_LENGTH = 4_096
MAX_ATTACHMENT_CONTENT = 7_000_000


class EmailAddress(BaseModel):
    name: str | None = Field(default=None, max_length=320)
    email: str = Field(min_length=3, max_length=320, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class AttachmentInfo(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    content_type: str | None = Field(default=None, max_length=255)
    size: int | None = Field(default=None, ge=0)
    content_base64: str | None = Field(default=None, max_length=MAX_ATTACHMENT_CONTENT)


class LinkInfo(BaseModel):
    text: str = Field(default="", max_length=2_048)
    href: str = Field(min_length=1, max_length=MAX_URL_LENGTH)

    @field_validator("href")
    @classmethod
    def validate_url_scheme(cls, value: str) -> str:
        if not value.lower().startswith(("http://", "https://")):
            raise ValueError("Link URL must use http or https.")
        return value


class EmailAnalysisRequest(BaseModel):
    subject: str = Field(default="", max_length=MAX_SUBJECT_LENGTH)
    sender: EmailAddress
    reply_to: str | None = Field(default=None, max_length=320)
    body: str = Field(default="", max_length=MAX_BODY_LENGTH)
    body_html: str | None = Field(default=None, max_length=MAX_HTML_LENGTH)
    headers: str = Field(default="", max_length=MAX_HEADERS_LENGTH)
    headers_status: str = Field(default="checked", pattern="^(checked|not_available|failed)$")
    attachment_content_status: str = Field(default="not_requested", pattern="^(checked|partial|not_available|failed|not_requested)$")
    internet_message_id: str | None = Field(default=None, max_length=998)
    received_at: str | None = Field(default=None, max_length=100)
    links: list[LinkInfo] = Field(default_factory=list, max_length=MAX_LINKS)
    attachments: list[AttachmentInfo] = Field(default_factory=list, max_length=MAX_ATTACHMENTS)


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
    ai_threshold: float = Field(default=0.5, ge=0, le=1)
    ai_evidence: list[str] = Field(default_factory=list)
    score_breakdown: list[ScoreComponent] = Field(default_factory=list)
    top_reasons: list[str] = Field(default_factory=list)
    url_count: int = 0
    attachment_count: int = 0
    attachment_hashes: list[str] = Field(default_factory=list)
    attachment_contents_inspected: int = 0
    attachment_content_status: str = "not_requested"
    authentication_headers_status: str = "not_available"
    authentication_status: str = "not_available"
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
