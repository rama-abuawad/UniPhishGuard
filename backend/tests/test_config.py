import json

import pytest
from pydantic import ValidationError

from app.config import load_settings


def _valid():
    return {
        "organization": {"name": "University", "sender_domains": ["example.edu"], "link_domains": ["example.edu"], "common_hosting_domains": [], "brand_terms": ["university"], "trusted_authserv_ids": ["mail.example.edu"]},
        "scoring": {"ai_phishing_weight": 10, "category_caps": {"other": 20}, "indicator_weights": {"rule": 5}, "indicator_categories": {"rule": "other"}, "verdict_thresholds": {"suspicious": 25, "phishing": 55, "high_risk": 80}},
    }


def _write(path, value):
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def test_valid_configuration_loads(tmp_path):
    assert load_settings(_write(tmp_path / "settings.json", _valid())).organization.name == "University"


def test_duplicate_domains_are_rejected(tmp_path):
    value = _valid(); value["organization"]["sender_domains"] = ["example.edu", "example.edu"]
    with pytest.raises(ValidationError): load_settings(_write(tmp_path / "settings.json", value))


def test_missing_indicator_mapping_is_rejected(tmp_path):
    value = _valid(); value["scoring"]["indicator_categories"] = {}
    with pytest.raises(ValidationError): load_settings(_write(tmp_path / "settings.json", value))


def test_misordered_thresholds_are_rejected(tmp_path):
    value = _valid(); value["scoring"]["verdict_thresholds"]["phishing"] = 20
    with pytest.raises(ValidationError): load_settings(_write(tmp_path / "settings.json", value))
