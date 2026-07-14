from __future__ import annotations

import re
from email.utils import parseaddr
from html import unescape
from urllib.parse import urlparse

from .ai import predict_email_risk
from .models import EmailAnalysisRequest, EmailAnalysisResponse, Indicator, ThreatCategory, ThreatLevel


URL_RE = re.compile(r"https?://[^\s<>\"]+", re.IGNORECASE)

# Trusted ADU and Microsoft domains.
TRUSTED_DOMAINS = {
    "adu.ac.ae",
    "info.adu.ac.ae",
    "students.adu.ac.ae",
    "university.edu",
    "office.com",
    "microsoft.com",
    "microsoftonline.com",
    "outlook.com",
}

# Words used to spot fake university branding.
UNIVERSITY_BRAND_TERMS = {
    "adu",
    "abu dhabi university",
    "university",
}

# Common university services used in scams.
UNIVERSITY_SERVICE_TERMS = {
    "hr": ("hr", "human resources", "recruitment", "payroll"),
    "student_affairs": ("student affairs", "student services", "registrar", "admissions"),
    "it_helpdesk": ("it helpdesk", "it support", "service desk", "password reset", "account verification"),
    "blackboard": ("blackboard", "learning management", "lms"),
    "microsoft_365": ("microsoft 365", "office 365", "outlook", "teams", "onedrive"),
    "scholarships": ("scholarship", "financial aid", "grant", "tuition award"),
    "internships": ("internship", "career office", "placement", "trainee program"),
}

# Keywords for phishing category labels.
THREAT_CATEGORY_RULES = (
    (
        "credential_theft",
        "Credential Theft",
        ("password", "verify your account", "login", "sign in", "credentials", "account locked", "mfa"),
    ),
    (
        "business_email_compromise",
        "Business Email Compromise",
        ("wire transfer", "bank details", "payment urgently", "gift card", "confidential request", "ceo"),
    ),
    (
        "scholarship_scam",
        "Scholarship Scam",
        ("scholarship", "financial aid", "grant", "tuition award", "application fee"),
    ),
    (
        "internship_scam",
        "Internship Scam",
        ("internship", "job offer", "trainee", "placement", "remote work", "processing fee"),
    ),
    (
        "fake_hr",
        "Fake HR",
        ("hr", "human resources", "payroll", "employee record", "recruitment"),
    ),
    (
        "invoice_scam",
        "Invoice Scam",
        ("invoice", "purchase order", "overdue payment", "remittance", "bank account"),
    ),
    (
        "malware_delivery",
        "Malware Delivery",
        ("download attachment", "enable macros", "protected document", "view document", "attached file"),
    ),
    (
        "microsoft_login_scam",
        "Microsoft Login Scam",
        ("microsoft 365", "office 365", "outlook", "teams", "onedrive", "microsoft account"),
    ),
)
HIGH_RISK_EXTENSIONS = {
    ".exe",
    ".scr",
    ".js",
    ".vbs",
    ".bat",
    ".cmd",
    ".ps1",
    ".iso",
    ".lnk",
}


def analyze_email(email: EmailAnalysisRequest) -> EmailAnalysisResponse:
    indicators: list[Indicator] = []
    url_count = _count_urls(email.body)

    indicators.extend(_check_sender_reply_to(email))
    indicators.extend(_check_authentication_results(email.headers))
    indicators.extend(_check_urls(email.body))
    indicators.extend(_check_attachments(email))
    indicators.extend(_check_university_impersonation(email))

    ai_prediction, ai_confidence = predict_email_risk(email)
    trusted_context = _has_trusted_university_context(email)
    if ai_prediction == "phishing" and not trusted_context:
        indicators.append(
            Indicator(
                code="ai_phishing_signal",
                severity="medium",
                message="AI text analysis found phishing-like wording.",
            )
        )

    categories = _detect_threat_categories(email, indicators)
    score = _score(indicators, ai_prediction, ai_confidence, categories)
    return EmailAnalysisResponse(
        verdict=_verdict(score),
        risk_score=score,
        threat_level=_threat_level(score),
        threat_categories=categories,
        ai_prediction=ai_prediction,
        ai_confidence=ai_confidence,
        url_count=url_count,
        attachment_count=len(email.attachments),
        indicators=indicators,
        recommended_actions=_recommended_actions(score, indicators),
    )


def _check_sender_reply_to(email: EmailAnalysisRequest) -> list[Indicator]:
    sender_domain = _domain_from_address(str(email.sender.email))
    reply_domain = _domain_from_address(email.reply_to or "")

    if sender_domain and reply_domain and sender_domain != reply_domain:
        return [
            Indicator(
                code="reply_to_mismatch",
                severity="medium",
                message="Reply-To domain is different from the sender domain.",
            )
        ]
    return []


def _check_authentication_results(headers: str) -> list[Indicator]:
    lowered = headers.lower()
    indicators: list[Indicator] = []

    for protocol in ("spf", "dkim", "dmarc"):
        if re.search(rf"\b{protocol}\s*=\s*(fail|softfail|permerror|temperror)", lowered):
            indicators.append(
                Indicator(
                    code=f"{protocol}_failed",
                    severity="high" if protocol == "dmarc" else "medium",
                    message=f"{protocol.upper()} check did not pass.",
                )
            )

    if "authentication-results" not in lowered and headers.strip():
        indicators.append(
            Indicator(
                code="auth_results_missing",
                severity="low",
                message="Authentication-Results header was not found.",
            )
        )

    return indicators


def _check_urls(body: str) -> list[Indicator]:
    text = _strip_html(body or "")
    urls = set(URL_RE.findall(f"{body} {text}"))
    indicators: list[Indicator] = []

    for url in urls:
        parsed = urlparse(url.rstrip(".,);]"))
        host = parsed.hostname or ""
        if _is_trusted_domain(host):
            continue
        if _is_ip_address(host):
            indicators.append(
                Indicator(
                    code="url_uses_ip_address",
                    severity="high",
                    message=f"URL uses an IP address instead of a normal domain: {host}",
                )
            )
        elif host.count("-") >= 2 or len(host) > 45:
            indicators.append(
                Indicator(
                    code="suspicious_url_domain",
                    severity="medium",
                    message=f"URL domain looks unusual: {host}",
                )
            )

    if len(urls) >= 5:
        indicators.append(
            Indicator(
                code="many_urls",
                severity="low",
                message="Email has many links.",
            )
        )

    return indicators


def _count_urls(body: str) -> int:
    text = _strip_html(body or "")
    return len(set(URL_RE.findall(f"{body} {text}")))


def _check_attachments(email: EmailAnalysisRequest) -> list[Indicator]:
    indicators: list[Indicator] = []

    for attachment in email.attachments:
        lowered_name = attachment.name.lower()
        if any(lowered_name.endswith(ext) for ext in HIGH_RISK_EXTENSIONS):
            indicators.append(
                Indicator(
                    code="dangerous_attachment_extension",
                    severity="high",
                    message=f"Attachment has a high-risk extension: {attachment.name}",
                )
            )
        elif re.search(r"\.(pdf|docx?|xlsx?|pptx?)\.(exe|scr|js|vbs|bat|cmd|ps1)$", lowered_name):
            indicators.append(
                Indicator(
                    code="double_extension_attachment",
                    severity="high",
                    message=f"Attachment uses a suspicious double extension: {attachment.name}",
                )
            )

    return indicators


def _check_university_impersonation(email: EmailAnalysisRequest) -> list[Indicator]:
    indicators: list[Indicator] = []
    text = _email_text(email)
    sender_domain = _domain_from_address(str(email.sender.email))
    hosts = _url_hosts(email.body)

    # Catches fake domains like adu-help.com or aduniversity-login.com.
    suspicious_domains = {
        domain
        for domain in {sender_domain, *hosts}
        if domain and not _is_trusted_domain(domain) and _looks_like_university_domain(domain)
    }

    for domain in sorted(suspicious_domains):
        indicators.append(
            Indicator(
                code="university_domain_impersonation",
                severity="high",
                message=f"Domain appears to imitate a university service: {domain}",
            )
        )

    if not _is_trusted_domain(sender_domain) and any(term in text for term in UNIVERSITY_BRAND_TERMS):
        indicators.append(
            Indicator(
                code="untrusted_university_branding",
                severity="medium",
                message="Email uses university branding but was not sent from a trusted university domain.",
            )
        )

    impersonated_services = _matched_university_services(text)
    if impersonated_services and not _has_trusted_university_context(email):
        indicators.append(
            Indicator(
                code="fake_university_service",
                severity="medium",
                message=f"Email appears to impersonate a university service: {', '.join(impersonated_services)}.",
            )
        )

    return indicators


def _detect_threat_categories(
    email: EmailAnalysisRequest,
    indicators: list[Indicator],
) -> list[ThreatCategory]:
    text = _email_text(email)
    categories: list[ThreatCategory] = []
    indicator_codes = {indicator.code for indicator in indicators}

    for code, label, keywords in THREAT_CATEGORY_RULES:
        matched = [keyword for keyword in keywords if keyword in text]
        if matched:
            categories.append(
                ThreatCategory(
                    code=code,
                    label=label,
                    confidence="high" if len(matched) >= 2 else "medium",
                    reason=f"Found phrase: {matched[0]}.",
                )
            )

    if "dangerous_attachment_extension" in indicator_codes or "double_extension_attachment" in indicator_codes:
        categories = _upsert_category(
            categories,
            ThreatCategory(
                code="malware_delivery",
                label="Malware Delivery",
                confidence="high",
                reason="Attachment pattern is commonly used to deliver malware.",
            ),
        )

    if "fake_university_service" in indicator_codes:
        for service in _matched_university_services(text):
            service_code = {
                "HR": "fake_hr",
                "Scholarships": "scholarship_scam",
                "Internships": "internship_scam",
                "Microsoft 365": "microsoft_login_scam",
            }.get(service)
            if service_code and service_code not in {category.code for category in categories}:
                label = next(rule[1] for rule in THREAT_CATEGORY_RULES if rule[0] == service_code)
                categories.append(
                    ThreatCategory(
                        code=service_code,
                        label=label,
                        confidence="medium",
                        reason=f"Message claims to come from {service}.",
                    )
                )

    return categories[:5]


def _upsert_category(categories: list[ThreatCategory], category: ThreatCategory) -> list[ThreatCategory]:
    return [existing for existing in categories if existing.code != category.code] + [category]


def _email_text(email: EmailAnalysisRequest) -> str:
    return " ".join(
        [
            email.subject or "",
            email.sender.name or "",
            str(email.sender.email),
            email.reply_to or "",
            _strip_html(email.body or ""),
        ]
    ).lower()


def _matched_university_services(text: str) -> list[str]:
    labels = {
        "hr": "HR",
        "student_affairs": "Student Affairs",
        "it_helpdesk": "IT Helpdesk",
        "blackboard": "Blackboard",
        "microsoft_365": "Microsoft 365",
        "scholarships": "Scholarships",
        "internships": "Internships",
    }
    return [
        labels[code]
        for code, keywords in UNIVERSITY_SERVICE_TERMS.items()
        if any(keyword in text for keyword in keywords)
    ]


def _looks_like_university_domain(domain: str) -> bool:
    normalized = re.sub(r"[^a-z0-9]", "", domain.lower())
    if normalized.startswith("adu") or "aduniversity" in normalized or "abudhabiuniversity" in normalized:
        return True

    university_words = ("help", "support", "login", "portal", "blackboard", "student", "hr")
    return "adu" in normalized and any(word in normalized for word in university_words)


def _score(
    indicators: list[Indicator],
    ai_prediction: str,
    ai_confidence: float,
    categories: list[ThreatCategory],
) -> int:
    # Simple score weights for the risk meter.
    severity_weights = {"low": 8, "medium": 18, "high": 30}
    score = sum(severity_weights.get(indicator.severity, 0) for indicator in indicators)

    if ai_prediction == "phishing":
        score += round(16 * ai_confidence)

    if categories:
        score += min(12, 4 * len(categories))

    return max(0, min(score, 100))


def _verdict(score: int) -> str:
    if score >= 80:
        return "High-risk phishing"
    if score >= 55:
        return "Likely phishing"
    if score >= 25:
        return "Suspicious"
    return "Likely legitimate"


def _threat_level(score: int) -> ThreatLevel:
    if score >= 80:
        return ThreatLevel(code="critical", label="Critical", color="#c93232", score_floor=80)
    if score >= 55:
        return ThreatLevel(code="high_risk", label="High Risk", color="#d45500", score_floor=55)
    if score >= 25:
        return ThreatLevel(code="suspicious", label="Suspicious", color="#c87816", score_floor=25)
    return ThreatLevel(code="safe", label="Safe", color="#1f7a4d", score_floor=0)


def _recommended_actions(score: int, indicators: list[Indicator]) -> list[str]:
    if score < 25:
        return ["No major phishing signs were found. Still be careful."]

    actions = [
        "Do not click links or open attachments yet.",
        "Check the sender using an official university channel.",
    ]

    if any(indicator.severity == "high" for indicator in indicators):
        actions.append("Report the email to the university IT team.")

    return actions


def _domain_from_address(address: str) -> str:
    parsed = parseaddr(address)[1] or address
    if "@" not in parsed:
        return ""
    return parsed.rsplit("@", 1)[1].lower().strip()


def _has_trusted_university_context(email: EmailAnalysisRequest) -> bool:
    sender_domain = _domain_from_address(str(email.sender.email))
    if _is_trusted_domain(sender_domain):
        return True

    hosts = _url_hosts(email.body)
    return bool(hosts) and all(_is_trusted_domain(host) for host in hosts)


def _url_hosts(body: str) -> set[str]:
    text = _strip_html(body or "")
    hosts = set()
    for url in set(URL_RE.findall(f"{body} {text}")):
        parsed = urlparse(url.rstrip(".,);]"))
        if parsed.hostname:
            hosts.add(parsed.hostname.lower())
    return hosts


def _is_trusted_domain(host: str) -> bool:
    host = (host or "").lower().strip()
    return any(host == domain or host.endswith(f".{domain}") for domain in TRUSTED_DOMAINS)


def _is_ip_address(host: str) -> bool:
    return bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host))


def _strip_html(value: str) -> str:
    without_tags = re.sub(r"<[^>]+>", " ", value)
    return unescape(without_tags)
