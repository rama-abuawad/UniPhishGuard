from pathlib import Path

import pytest

from app import ai


def test_valid_model_checksum():
    ai._verify_model_integrity()


def test_modified_model_is_rejected(monkeypatch):
    monkeypatch.setattr(ai, "_sha256", lambda path: "modified-checksum")
    with pytest.raises(RuntimeError, match="checksum"):
        ai._verify_model_integrity()


def test_missing_integrity_data_is_rejected(monkeypatch):
    monkeypatch.setattr(ai, "INTEGRITY_PATH", Path("missing-integrity-file.json"))
    monkeypatch.setenv("APP_ENV", "production")
    with pytest.raises(RuntimeError, match="integrity"):
        ai._verify_model_integrity()


def test_production_rejects_sklearn_version_mismatch(monkeypatch):
    monkeypatch.setattr(ai, "METRICS_PATH", Path(__file__).parent / "fixtures" / "incompatible_metrics.json")
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.delenv("ALLOW_MODEL_VERSION_MISMATCH", raising=False)
    with pytest.raises(RuntimeError, match="scikit-learn"):
        ai._check_model_metadata()
