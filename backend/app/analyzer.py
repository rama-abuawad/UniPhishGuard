from __future__ import annotations

import re
from email.utils import parseaddr
from html import unescape
from urllib.parse import urlparse

from .ai import predict_email_risk
from .models import EmailAnalysisRequest, EmailAnalysisResponse, Indicator


URL_RE = re.compile(r"https?://[^\s<>\"]+", re.IGNORECASE)
TRUSTED_DOMAINS = {
    "adu.ac.ae",
    "info.adu.ac.ae",
    "students.adu.ac.ae",
}
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

    score = _score(indicators, ai_prediction, ai_confidence)
    return EmailAnalysisResponse(
        verdict=_verdict(score),
        risk_score=score,
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


def _score(indicators: list[Indicator], ai_prediction: str, ai_confidence: float) -> int:
    # Basic weights used for the final score.
    severity_weights = {"low": 8, "medium": 18, "high": 30}
    score = sum(severity_weights.get(indicator.severity, 0) for indicator in indicators)

    if ai_prediction == "phishing":
        score += round(16 * ai_confidence)

    return max(0, min(score, 100))


def _verdict(score: int) -> str:
    if score >= 80:
        return "High-risk phishing"
    if score >= 55:
        return "Likely phishing"
    if score >= 25:
        return "Suspicious"
    return "Likely legitimate"


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
