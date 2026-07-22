from __future__ import annotations

import re
import base64
import binascii
import hashlib
import io
import zipfile
from pathlib import Path
from email.utils import parseaddr
from html.parser import HTMLParser
from html import unescape
from ipaddress import ip_address
from urllib.parse import parse_qs, unquote, urlparse

import cv2
import numpy as np

from .ai import explain_email_risk, predict_email_risk
from .config import load_settings
from .schemas import EmailAnalysisRequest, EmailAnalysisResponse, Indicator, LinkInfo, ScoreComponent, ThreatCategory, ThreatLevel


SETTINGS_PATH = Path(__file__).with_name("settings.json")
SETTINGS = load_settings(SETTINGS_PATH)


def organization_config() -> dict:
    return SETTINGS.organization.model_dump()


def scoring_config() -> dict:
    return SETTINGS.scoring.model_dump()


URL_RE = re.compile(r"https?://[^\s<>\"]+", re.IGNORECASE)

ORG_CONFIG = organization_config()
SCORING_CONFIG = scoring_config()
APPROVED_SENDER_DOMAINS = set(ORG_CONFIG["sender_domains"])
APPROVED_LINK_DOMAINS = set(ORG_CONFIG["link_domains"])
COMMON_HOSTING_DOMAINS = set(ORG_CONFIG["common_hosting_domains"])
TRUSTED_AUTHSERV_IDS = set(ORG_CONFIG["trusted_authserv_ids"])

URL_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
    "rebrand.ly",
}

# Words used to spot fake university branding.
UNIVERSITY_BRAND_TERMS = set(ORG_CONFIG["brand_terms"])

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
THREAT_CATEGORY_REASON_TEMPLATES = {
    "credential_theft": "This email may be asking for account access.",
    "business_email_compromise": "This email may involve a money-related request.",
    "scholarship_scam": "This email may be using financial aid details.",
    "internship_scam": "This email may be using job or internship details.",
    "fake_hr": "This email may be pretending to be HR or staff support.",
    "invoice_scam": "This email may be using payment or invoice details.",
    "malware_delivery": "This email may be trying to make you open a file or download.",
    "microsoft_login_scam": "This email may be using Microsoft sign-in details.",
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
MACRO_EXTENSIONS = {".docm", ".xlsm", ".pptm"}
ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z"}
AUTH_FAILURE_MESSAGES = {
    "spf": "SPF warning: the sending server was not approved for this sender domain.",
    "dkim": (
        "DKIM warning: the email signature could not be verified. "
        "This can happen with forwarding or sender setup issues, but be careful if the email asks for links, files, or personal information."
    ),
    "dmarc": "DMARC warning: the sender domain did not pass the main anti-spoofing policy.",
}
AUTH_PLAIN_NAMES = {
    "spf": "sender-server check",
    "dkim": "DKIM signature check",
    "dmarc": "DMARC anti-spoofing check",
}
AUTH_PLAIN_EXPLANATIONS = {
    "spf": "server not confirmed",
    "dkim": "sender signature not confirmed",
    "dmarc": "sender domain not confirmed",
}
AUTH_BAD_RESULTS = {"fail", "softfail", "permerror", "temperror"}
AUTH_PASS_RESULTS = {"pass"}
AUTH_INCONCLUSIVE_RESULTS = {"neutral", "none", "policy", "bestguesspass"}
MAX_ATTACHMENT_BYTES = 5_000_000
MAX_ZIP_ENTRIES = 50
MAX_ZIP_UNCOMPRESSED_BYTES = 20_000_000


def analyze_email(email: EmailAnalysisRequest) -> EmailAnalysisResponse:
    indicators: list[Indicator] = []
    links = _collect_links(email)
    attachment_indicators, attachment_hashes, qr_links = _check_attachments(email)
    links.extend(qr_links)
    url_count = len({link.href for link in links})

    indicators.extend(_check_sender_reply_to(email))
    indicators.extend(_check_authentication_results(email.headers, email.headers_status))
    indicators.extend(_check_urls(email, links))
    indicators.extend(attachment_indicators)
    indicators.extend(_check_university_impersonation(email))
    indicators = _deduplicate_indicators(indicators)

    ai_prediction, ai_confidence = predict_email_risk(email)
    ai_evidence = explain_email_risk(email)
    trusted_context = _has_trusted_sender_context(email)
    if ai_prediction == "phishing" and not trusted_context and ai_confidence >= 0.75:
        indicators.append(
            Indicator(
                code="ai_phishing_signal",
                severity="medium",
                message=f"AI text analysis found phishing-like wording ({round(ai_confidence * 100)}%).",
            )
        )

    categories = _detect_threat_categories(email, indicators)
    score, score_breakdown = _score(indicators, ai_prediction, ai_confidence)
    return EmailAnalysisResponse(
        verdict=_verdict(score),
        risk_score=score,
        threat_level=_threat_level(score),
        threat_categories=categories,
        ai_prediction=ai_prediction,
        ai_confidence=ai_confidence,
        ai_evidence=ai_evidence,
        score_breakdown=score_breakdown,
        top_reasons=_top_reasons(indicators, ai_evidence),
        url_count=url_count,
        attachment_count=len(email.attachments),
        attachment_hashes=attachment_hashes,
        decoded_qr_links=qr_links,
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


def _check_authentication_results(headers: str, status: str = "checked") -> list[Indicator]:
    if status != "checked":
        return [
            Indicator(
                code="auth_headers_not_checked",
                severity="low",
                message="Email authentication headers were not checked in this Outlook client.",
            )
        ]

    lowered = headers.lower()
    indicators: list[Indicator] = []

    if not headers.strip():
        return [
            Indicator(
                code="auth_headers_not_checked",
                severity="low",
                message="Email authentication headers were not available, so SPF, DKIM, and DMARC were not checked.",
            )
        ]

    auth_blocks = _authentication_result_blocks(headers)
    trusted_blocks = [block for block in auth_blocks if _trusted_authentication_block(block)]
    if auth_blocks and not trusted_blocks:
        return [Indicator(
            code="auth_results_untrusted",
            severity="low",
            message="Authentication results were present but were not issued by a configured trusted mail server.",
        )]
    auth_blocks = trusted_blocks
    parsed_results = _parse_authentication_results(auth_blocks)

    for protocol in ("spf", "dkim", "dmarc"):
        results = parsed_results.get(protocol, [])
        bad_results = [result for result in results if result["result"] in AUTH_BAD_RESULTS]
        pass_results = [result for result in results if result["result"] in AUTH_PASS_RESULTS]
        unclear_results = [result for result in results if result["result"] in AUTH_INCONCLUSIVE_RESULTS]

        if bad_results and not pass_results:
            indicators.append(
                Indicator(
                    code=f"{protocol}_failed",
                    severity="high" if protocol == "dmarc" else "medium",
                    message=AUTH_FAILURE_MESSAGES[protocol],
                )
            )
        elif bad_results and pass_results:
            indicators.append(
                Indicator(
                    code=f"{protocol}_inconclusive",
                    severity="low",
                    message=f"{protocol.upper()} had mixed results. This can happen with forwarding or mailing lists.",
                )
            )
        elif unclear_results and not pass_results:
            indicators.append(
                Indicator(
                    code=f"{protocol}_inconclusive",
                    severity="low",
                    message=(
                        f"{AUTH_PLAIN_NAMES[protocol]} was unclear: "
                        f"{AUTH_PLAIN_EXPLANATIONS[protocol]}. Review the other warnings too."
                    ),
                )
            )

    if _has_auth_alignment_problem(auth_blocks):
        indicators.append(
            Indicator(
                code="auth_alignment_warning",
                severity="medium",
                message="Email authentication passed somewhere, but sender-domain alignment looks suspicious.",
            )
        )

    if "arc-authentication-results" in lowered and any(
        indicator.code.endswith("_failed") for indicator in indicators
    ):
        indicators.append(
            Indicator(
                code="forwarding_or_arc_context",
                severity="low",
                message="ARC/forwarding headers are present, so authentication failures should be reviewed with the sender context.",
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


def _check_urls(email: EmailAnalysisRequest, links: list[LinkInfo]) -> list[Indicator]:
    urls = {link.href for link in links}
    indicators: list[Indicator] = []

    for link in links:
        url = _clean_url(link.href)
        parsed = urlparse(url)
        host = _normalize_host(parsed.hostname or "")
        display_host = _displayed_host(link.text)

        if display_host and host and display_host != host and not _same_registrable_domain(display_host, host):
            indicators.append(
                Indicator(
                    code="link_text_destination_mismatch",
                    severity="high",
                    message=f"Link text shows {display_host}, but it actually opens {host}.",
                )
            )
            if _is_approved_link_domain(display_host) and not _is_approved_link_domain(host):
                indicators.append(
                    Indicator(
                        code="approved_domain_displayed_for_untrusted_link",
                        severity="medium",
                        message="The link displays an approved university domain but opens an unapproved domain.",
                    )
                )

        if _is_approved_link_domain(host):
            continue

        if _is_common_hosting_domain(host):
            sender_domain = _domain_from_address(str(email.sender.email))
            if not _is_approved_sender_domain(sender_domain):
                indicators.append(
                    Indicator(
                        code="external_sender_common_hosting_link",
                        severity="low",
                        message=f"External sender uses a common hosting or Microsoft link: {host}.",
                    )
                )
            continue

        if parsed.username or parsed.password:
            indicators.append(
                Indicator(
                    code="url_uses_user_info",
                    severity="high",
                    message=f"URL hides the real destination with user-info text: {host}",
                )
            )
        if parsed.port and parsed.port not in {80, 443}:
            indicators.append(
                Indicator(
                    code="url_unusual_port",
                    severity="medium",
                    message=f"URL uses an unusual port: {host}:{parsed.port}",
                )
            )
        if host in URL_SHORTENERS:
            indicators.append(
                Indicator(
                    code="url_shortener",
                    severity="medium",
                    message=f"URL uses a link shortener: {host}",
                )
            )
        if "%" in url or unquote(url) != url:
            indicators.append(
                Indicator(
                    code="encoded_url",
                    severity="medium",
                    message=f"URL contains encoded characters: {host}",
                )
            )
        if _is_ip_address(host):
            indicators.append(
                Indicator(
                    code="url_uses_ip_address",
                    severity="high",
                    message=f"URL uses an IP address instead of a normal domain: {host}",
                )
            )
        elif host.startswith("xn--") or ".xn--" in host:
            indicators.append(
                Indicator(
                    code="punycode_domain",
                    severity="high",
                    message=f"URL uses an internationalized/punycode domain: {host}",
                )
            )
        elif host.count("-") >= 2 or len(host) > 45 or _looks_like_university_domain(host):
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


def _deduplicate_indicators(indicators: list[Indicator]) -> list[Indicator]:
    unique: list[Indicator] = []
    seen: set[tuple[str, str]] = set()
    for indicator in indicators:
        key = (indicator.code, indicator.message)
        if key not in seen:
            seen.add(key)
            unique.append(indicator)
    return unique


def _authentication_result_blocks(headers: str) -> list[str]:
    blocks: list[str] = []
    current: list[str] = []

    for line in headers.splitlines():
        lowered = line.lower()
        if lowered.startswith(("authentication-results:", "arc-authentication-results:")):
            if current:
                blocks.append(" ".join(current))
            current = [line]
        elif current and (line.startswith((" ", "\t")) or "=" in line):
            current.append(line.strip())
        elif current:
            blocks.append(" ".join(current))
            current = []

    if current:
        blocks.append(" ".join(current))

    return blocks


def _parse_authentication_results(blocks: list[str]) -> dict[str, list[dict[str, str]]]:
    results: dict[str, list[dict[str, str]]] = {"spf": [], "dkim": [], "dmarc": []}

    for block in blocks:
        lowered = block.lower()
        for protocol in results:
            for match in re.finditer(rf"\b{protocol}\s*=\s*([a-z]+)", lowered):
                result = match.group(1)
                window = lowered[match.start() : match.start() + 220]
                domain_match = re.search(r"\b(?:smtp\.mailfrom|header\.d|header\.from)=([^;\s]+)", window)
                results[protocol].append(
                    {
                        "result": result,
                        "domain": (domain_match.group(1).strip().strip(";") if domain_match else ""),
                    }
                )

    return results


def _trusted_authentication_block(block: str) -> bool:
    match = re.search(r"(?:arc-)?authentication-results:\s*(?:i=\d+;\s*)?([^;\s]+)", block, re.IGNORECASE)
    if not match:
        return False
    authserv_id = match.group(1).strip().lower().rstrip(".")
    return any(authserv_id == trusted or authserv_id.endswith(f".{trusted}") for trusted in TRUSTED_AUTHSERV_IDS)


def _has_auth_alignment_problem(blocks: list[str]) -> bool:
    for block in blocks:
        lowered = block.lower()
        if "dmarc=pass" in lowered and re.search(r"\bheader\.from=[^;\s]+", lowered):
            continue
        if re.search(r"\bdmarc\s*=\s*fail\b", lowered):
            return True
        if re.search(r"\b(alignment|aligned)\s*=\s*(fail|none|no)\b", lowered):
            return True
    return False


def _check_attachments(email: EmailAnalysisRequest) -> tuple[list[Indicator], list[str], list[LinkInfo]]:
    indicators: list[Indicator] = []
    hashes: list[str] = []
    qr_links: list[LinkInfo] = []

    for attachment in email.attachments:
        lowered_name = _normalize_filename(attachment.name)
        final_ext = _final_extension(lowered_name)
        content_type = (attachment.content_type or "").lower()
        content = _safe_attachment_bytes(attachment.content_base64)

        double_match = re.search(r"\.(pdf|docx?|xlsx?|pptx?)\.(exe|scr|js|vbs|bat|cmd|ps1)$", lowered_name)
        if double_match:
            indicators.append(
                Indicator(
                    code="double_extension_attachment",
                    severity="high",
                    message=f"Attachment uses a deceptive double extension: {attachment.name}",
                )
            )
        elif final_ext in HIGH_RISK_EXTENSIONS:
            indicators.append(
                Indicator(
                    code="dangerous_attachment_extension",
                    severity="high",
                    message=f"Attachment has a high-risk extension: {attachment.name}",
                )
            )
        elif final_ext in MACRO_EXTENSIONS:
            indicators.append(
                Indicator(
                    code="macro_enabled_attachment",
                    severity="medium",
                    message=f"Attachment is a macro-enabled Office file: {attachment.name}",
                )
            )
        elif final_ext in ARCHIVE_EXTENSIONS:
            indicators.append(
                Indicator(
                    code="archive_attachment",
                    severity="low",
                    message=f"Attachment is an archive file and its contents were not opened: {attachment.name}",
                )
            )

        if _mime_extension_mismatch(final_ext, content_type):
            indicators.append(
                Indicator(
                    code="attachment_mime_mismatch",
                    severity="medium",
                    message=f"Attachment type does not match the filename: {attachment.name}",
                )
            )

        if content:
            hashes.append(hashlib.sha256(content).hexdigest())
            indicators.extend(_inspect_zip_attachment(attachment.name, content, final_ext, content_type))
            decoded_link = _decode_qr_attachment(attachment.name, content, content_type)
            if decoded_link:
                qr_links.append(decoded_link)
                indicators.append(
                    Indicator(
                        code="qr_code_link_detected",
                        severity="medium",
                        message=f"QR code in attachment points to: {decoded_link.href}",
                    )
                )

    return indicators, hashes, qr_links


def _safe_attachment_bytes(content_base64: str | None) -> bytes | None:
    if not content_base64:
        return None
    try:
        content = base64.b64decode(content_base64, validate=True)
    except (binascii.Error, ValueError):
        return None
    if len(content) > MAX_ATTACHMENT_BYTES:
        return None
    return content


def _inspect_zip_attachment(name: str, content: bytes, ext: str, content_type: str) -> list[Indicator]:
    if ext != ".zip" and "zip" not in content_type and not zipfile.is_zipfile(io.BytesIO(content)):
        return []

    indicators: list[Indicator] = []
    try:
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            entries = archive.infolist()
            total_size = sum(entry.file_size for entry in entries)
            if len(entries) > MAX_ZIP_ENTRIES or total_size > MAX_ZIP_UNCOMPRESSED_BYTES:
                indicators.append(
                    Indicator(
                        code="zip_limits_exceeded",
                        severity="medium",
                        message=f"ZIP attachment is too large or complex to inspect fully: {name}",
                    )
                )
                return indicators

            for entry in entries:
                entry_name = _normalize_filename(entry.filename)
                entry_ext = _final_extension(entry_name)
                if entry_ext in HIGH_RISK_EXTENSIONS or entry_ext in MACRO_EXTENSIONS:
                    indicators.append(
                        Indicator(
                            code="zip_contains_risky_file",
                            severity="high",
                            message=f"ZIP attachment contains a risky file: {entry.filename}",
                        )
                    )
                    break
    except zipfile.BadZipFile:
        indicators.append(
            Indicator(
                code="zip_attachment_unreadable",
                severity="medium",
                message=f"ZIP attachment could not be inspected safely: {name}",
            )
        )
    return indicators


def _decode_qr_attachment(name: str, content: bytes, content_type: str) -> LinkInfo | None:
    if not content_type.startswith("image/") and _final_extension(_normalize_filename(name)) not in {".png", ".jpg", ".jpeg"}:
        return None
    data = np.frombuffer(content, dtype=np.uint8)
    image = cv2.imdecode(data, cv2.IMREAD_GRAYSCALE)
    if image is None:
        return None
    detector = cv2.QRCodeDetector()
    value, _, _ = detector.detectAndDecode(image)
    value = (value or "").strip()
    if value.lower().startswith(("http://", "https://")):
        return LinkInfo(text="QR code link", href=value)
    return None


def _check_university_impersonation(email: EmailAnalysisRequest) -> list[Indicator]:
    indicators: list[Indicator] = []
    text = _email_text(email)
    text_without_urls = URL_RE.sub(" ", text)
    sender_domain = _domain_from_address(str(email.sender.email))
    hosts = _url_hosts(email)

    # Catches fake domains like adu-help.com or aduniversity-login.com.
    suspicious_domains = {
        domain
        for domain in {sender_domain, *hosts}
        if domain and not _is_approved_link_domain(domain) and not _is_approved_sender_domain(domain) and _looks_like_university_domain(domain)
    }

    for domain in sorted(suspicious_domains):
        indicators.append(
            Indicator(
                code="university_domain_impersonation",
                severity="high",
                message=f"Domain appears to imitate a university service: {domain}",
            )
        )

    has_untrusted_brand = not _is_approved_sender_domain(sender_domain) and any(
        term in text_without_urls for term in UNIVERSITY_BRAND_TERMS
    )
    if has_untrusted_brand:
        indicators.append(
            Indicator(
                code="untrusted_university_branding",
                severity="medium",
                message="Email uses university branding but was not sent from a trusted university domain.",
            )
        )

    impersonated_services = _matched_university_services(text)
    if (
        impersonated_services
        and not _has_trusted_sender_context(email)
        and (suspicious_domains or has_untrusted_brand or _has_account_action_terms(text))
    ):
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
    category_context = any(indicator.severity in {"medium", "high"} for indicator in indicators)

    if category_context:
        for code, label, keywords in THREAT_CATEGORY_RULES:
            matched = [keyword for keyword in keywords if keyword in text]
            if matched:
                categories.append(
                    ThreatCategory(
                        code=code,
                        label=label,
                        evidence_strength="high" if len(matched) >= 2 else "medium",
                        reason=THREAT_CATEGORY_REASON_TEMPLATES[code],
                    )
                )

    if "dangerous_attachment_extension" in indicator_codes or "double_extension_attachment" in indicator_codes:
        categories = _upsert_category(
            categories,
            ThreatCategory(
                code="malware_delivery",
                label="Malware Delivery",
                evidence_strength="high",
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
                        evidence_strength="medium",
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
            _strip_html(email.body_html or ""),
            " ".join(f"{link.text} {link.href}" for link in email.links),
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


def _has_account_action_terms(text: str) -> bool:
    action_terms = (
        "verify",
        "password",
        "sign in",
        "login",
        "account locked",
        "update your account",
        "confirm your account",
    )
    return any(term in text for term in action_terms)


def _score(
    indicators: list[Indicator],
    ai_prediction: str,
    ai_confidence: float,
) -> tuple[int, list[ScoreComponent]]:
    indicator_weights = SCORING_CONFIG["indicator_weights"]
    indicator_categories = SCORING_CONFIG["indicator_categories"]
    caps = SCORING_CONFIG["category_caps"]
    raw_components = {category: 0 for category in caps}

    corroborated = any(
        indicator.code != "ai_phishing_signal" and indicator.severity in {"medium", "high"}
        for indicator in indicators
    )
    if ai_prediction == "phishing" and ai_confidence >= 0.75 and corroborated:
        raw_components["ai_language"] += round(SCORING_CONFIG["ai_phishing_weight"] * ai_confidence)

    for indicator in indicators:
        category = indicator_categories.get(indicator.code, "other")
        raw_components[category] = raw_components.get(category, 0) + indicator_weights.get(
            indicator.code,
            {"low": 6, "medium": 16, "high": 28}.get(indicator.severity, 0),
        )

    components = [
        ScoreComponent(
            code=code,
            label=_component_label(code),
            score=min(score, caps.get(code, 100)),
            cap=caps.get(code, 100),
        )
        for code, score in raw_components.items()
        if min(score, caps.get(code, 100)) > 0
    ]
    final_score = sum(component.score for component in components)
    return max(0, min(final_score, 100)), components


def _component_label(code: str) -> str:
    return {
        "ai_language": "AI Language",
        "authentication": "Sender Authentication",
        "sender_identity": "Sender Identity",
        "urls": "URL Analysis",
        "attachments": "Attachment Analysis",
        "university_impersonation": "University Impersonation",
        "other": "Other Evidence",
    }.get(code, code.replace("_", " ").title())


def _top_reasons(indicators: list[Indicator], ai_evidence: list[str]) -> list[str]:
    high_priority = [indicator.message for indicator in indicators if indicator.severity == "high"]
    medium_priority = [indicator.message for indicator in indicators if indicator.severity == "medium"]
    ai_reasons = [f"AI noticed: {phrase}" for phrase in ai_evidence[:2]]
    return (high_priority + medium_priority + ai_reasons)[:3]


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


def _has_trusted_sender_context(email: EmailAnalysisRequest) -> bool:
    sender_domain = _domain_from_address(str(email.sender.email))
    return _is_approved_sender_domain(sender_domain)


def _url_hosts(email: EmailAnalysisRequest) -> set[str]:
    hosts = set()
    for link in _collect_links(email):
        parsed = urlparse(_clean_url(link.href))
        if parsed.hostname:
            hosts.add(_normalize_host(parsed.hostname))
    return hosts


def _is_approved_sender_domain(host: str) -> bool:
    host = (host or "").lower().strip()
    return any(host == domain or host.endswith(f".{domain}") for domain in APPROVED_SENDER_DOMAINS)


def _is_approved_link_domain(host: str) -> bool:
    host = (host or "").lower().strip()
    return any(host == domain or host.endswith(f".{domain}") for domain in APPROVED_LINK_DOMAINS)


def _is_common_hosting_domain(host: str) -> bool:
    host = (host or "").lower().strip()
    return any(host == domain or host.endswith(f".{domain}") for domain in COMMON_HOSTING_DOMAINS)


def _is_ip_address(host: str) -> bool:
    try:
        ip_address(host)
        return True
    except ValueError:
        return False


def _strip_html(value: str) -> str:
    without_tags = re.sub(r"<[^>]+>", " ", value)
    return unescape(without_tags)


class _AnchorParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[LinkInfo] = []
        self._current_href: str | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() == "a":
            attrs_dict = {name.lower(): value for name, value in attrs}
            self._current_href = attrs_dict.get("href") or ""
            self._text = []

    def handle_data(self, data: str) -> None:
        if self._current_href is not None:
            self._text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "a" and self._current_href:
            self.links.append(LinkInfo(text=" ".join(self._text).strip()[:500], href=self._current_href.strip()))
            self._current_href = None
            self._text = []


def _collect_links(email: EmailAnalysisRequest) -> list[LinkInfo]:
    links = list(email.links)

    html = email.body_html or email.body or ""
    if "<a" in html.lower():
        parser = _AnchorParser()
        try:
            parser.feed(html)
            links.extend(parser.links)
        except Exception:
            pass

    plain = " ".join([email.body or "", _strip_html(email.body_html or "")])
    for url in URL_RE.findall(plain):
        links.append(LinkInfo(text=url[:500], href=url))

    seen: set[str] = set()
    unique: list[LinkInfo] = []
    for link in links:
        clean = _clean_url(link.href)
        if clean and clean not in seen and clean.lower().startswith(("http://", "https://")):
            unique.append(LinkInfo(text=(link.text or clean)[:500], href=clean))
            seen.add(clean)
    return unique


def _clean_url(url: str) -> str:
    cleaned = (url or "").strip().rstrip(".,);]")
    parsed = urlparse(cleaned)
    host = _normalize_host(parsed.hostname or "")
    if host == "safelinks.protection.outlook.com" or host.endswith(".safelinks.protection.outlook.com"):
        wrapped = parse_qs(parsed.query).get("url", [])
        if wrapped:
            return unquote(wrapped[0]).strip()
    return cleaned


def _normalize_host(host: str) -> str:
    host = (host or "").strip().strip(".").lower()
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError:
        return host


def _displayed_host(text: str) -> str:
    text = (text or "").strip()
    if not text:
        return ""
    match = URL_RE.search(text)
    if match:
        return _normalize_host(urlparse(_clean_url(match.group(0))).hostname or "")
    if re.fullmatch(r"(?:[a-z0-9-]+\.)+[a-z]{2,}", text.lower()):
        return _normalize_host(text)
    return ""


def _same_registrable_domain(left: str, right: str) -> bool:
    return _simple_registrable_domain(left) == _simple_registrable_domain(right)


def _simple_registrable_domain(host: str) -> str:
    parts = _normalize_host(host).split(".")
    if len(parts) <= 2:
        return ".".join(parts)
    if parts[-2] in {"ac", "edu", "co", "com", "net", "org"} and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _normalize_filename(name: str) -> str:
    return (name or "").strip().strip(".").lower().replace("\u202e", "")


def _final_extension(name: str) -> str:
    match = re.search(r"(\.[a-z0-9]+)$", name)
    return match.group(1) if match else ""


def _mime_extension_mismatch(ext: str, content_type: str) -> bool:
    if not content_type or not ext:
        return False
    expected = {
        ".pdf": "application/pdf",
        ".doc": "msword",
        ".docx": "wordprocessingml",
        ".xls": "excel",
        ".xlsx": "spreadsheetml",
        ".ppt": "powerpoint",
        ".pptx": "presentationml",
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".png": "image/png",
        ".txt": "text/plain",
    }
    marker = expected.get(ext)
    return bool(marker and marker not in content_type)
