import json
import re
from pathlib import Path

from pydantic import BaseModel, Field, field_validator, model_validator


DOMAIN_PATTERN = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


class OrganizationConfig(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    sender_domains: list[str] = Field(min_length=1)
    link_domains: list[str] = Field(min_length=1)
    common_hosting_domains: list[str]
    brand_terms: list[str] = Field(min_length=1)
    trusted_authserv_ids: list[str] = Field(min_length=1)

    @field_validator("sender_domains", "link_domains", "common_hosting_domains", "trusted_authserv_ids")
    @classmethod
    def validate_domains(cls, values: list[str]) -> list[str]:
        normalized = [value.strip().lower() for value in values]
        if len(normalized) != len(set(normalized)):
            raise ValueError("Domain lists must not contain duplicates.")
        if any(not DOMAIN_PATTERN.fullmatch(value) for value in normalized):
            raise ValueError("Configuration contains an invalid domain.")
        return normalized


class ScoringConfig(BaseModel):
    ai_phishing_weight: int = Field(ge=0, le=100)
    category_caps: dict[str, int]
    indicator_weights: dict[str, int]
    indicator_categories: dict[str, str]
    verdict_thresholds: dict[str, int]

    @model_validator(mode="after")
    def validate_mappings(self):
        if set(self.indicator_weights) != set(self.indicator_categories):
            raise ValueError("Every indicator weight must have exactly one category mapping.")
        if any(value < 0 or value > 100 for value in self.indicator_weights.values()):
            raise ValueError("Indicator weights must be between 0 and 100.")
        if any(value < 0 or value > 100 for value in self.category_caps.values()):
            raise ValueError("Category caps must be between 0 and 100.")
        unknown = set(self.indicator_categories.values()) - set(self.category_caps)
        if unknown:
            raise ValueError(f"Unknown indicator categories: {sorted(unknown)}")
        required = {"suspicious", "phishing", "high_risk"}
        if set(self.verdict_thresholds) != required:
            raise ValueError("Verdict thresholds must define suspicious, phishing, and high_risk.")
        values = [self.verdict_thresholds[key] for key in ("suspicious", "phishing", "high_risk")]
        if not (0 < values[0] < values[1] < values[2] <= 100):
            raise ValueError("Verdict thresholds must be strictly increasing.")
        return self


class AppSettings(BaseModel):
    organization: OrganizationConfig
    scoring: ScoringConfig


def load_settings(path: Path) -> AppSettings:
    return AppSettings.model_validate(json.loads(path.read_text(encoding="utf-8-sig")))
