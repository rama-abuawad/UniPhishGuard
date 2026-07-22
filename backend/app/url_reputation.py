from __future__ import annotations

import json
import os
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlparse
from urllib.request import Request, urlopen

from .schemas import Indicator


WEB_RISK_ENDPOINT = "https://webrisk.googleapis.com/v1/uris:search"
THREAT_TYPES = ("MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE")
MAX_REPUTATION_URLS = int(os.getenv("URL_REPUTATION_MAX_URLS", "20"))
REPUTATION_TIMEOUT_SECONDS = float(os.getenv("URL_REPUTATION_TIMEOUT_SECONDS", "3"))


def check_url_reputation(urls: set[str]) -> tuple[list[Indicator], int, str]:
    """Check HTTP(S) URLs with Google Web Risk when a server-side key is configured."""
    api_key = os.getenv("GOOGLE_WEB_RISK_API_KEY", "").strip()
    if not api_key:
        return [], 0, "not_configured"

    candidates = sorted({_valid_url(url) for url in urls if _valid_url(url)})[:MAX_REPUTATION_URLS]
    indicators: list[Indicator] = []
    checked = 0

    for url in candidates:
        try:
            threat_types = [("threatTypes", threat_type) for threat_type in THREAT_TYPES]
            query = urlencode([("uri", url), *threat_types, ("key", api_key)])
            request = Request(f"{WEB_RISK_ENDPOINT}?{query}", headers={"Accept": "application/json"})
            with urlopen(request, timeout=REPUTATION_TIMEOUT_SECONDS) as response:
                payload = json.loads(response.read().decode("utf-8"))
            checked += 1
        except (HTTPError, URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError):
            return indicators, checked, "unavailable"

        matches = payload.get("threat", {}).get("threatTypes", [])
        if matches:
            host = urlparse(url).hostname or "URL"
            readable = ", ".join(str(value).replace("_", " ").lower() for value in matches)
            indicators.append(
                Indicator(
                    code="external_url_reputation_match",
                    severity="high",
                    message=f"External reputation service flags {host} for {readable}.",
                )
            )

    return indicators, checked, "checked"


def _valid_url(value: str) -> str | None:
    value = value.strip()
    parsed = urlparse(value)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return None
    return value
