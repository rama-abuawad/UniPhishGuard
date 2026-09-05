import sqlite3

from app import db
from app.schemas import EmailAddress, EmailAnalysisRequest, EmailAnalysisResponse, ThreatLevel


def _email(index=0):
    return EmailAnalysisRequest(subject=f"Subject {index}", sender=EmailAddress(email="person@example.com"), body="PRIVATE BODY", headers="PRIVATE HEADERS")


def _result():
    return EmailAnalysisResponse(verdict="Likely legitimate", risk_score=0, threat_level=ThreatLevel(code="safe", label="Safe", color="#000000", score_floor=0), ai_prediction="legitimate", ai_confidence=0.1, indicators=[], recommended_actions=[])


def test_history_does_not_store_message_content_or_plain_sender(monkeypatch, tmp_path):
    path = tmp_path / "history.db"; monkeypatch.setattr(db, "DB_PATH", path)
    db.save_scan(_email(), _result(), "user-a")
    raw = path.read_bytes()
    assert b"PRIVATE BODY" not in raw and b"PRIVATE HEADERS" not in raw and b"person@example.com" not in raw
    assert b"user-a" not in raw


def test_history_removes_links_emails_and_control_characters_from_subject(monkeypatch, tmp_path):
    path = tmp_path / "history.db"; monkeypatch.setattr(db, "DB_PATH", path)
    email = _email().model_copy(update={"subject": "Contact private@example.com\r\n at https://private.example/reset"})
    db.save_scan(email, _result(), "user-a")
    item = db.get_history("user-a")[0]
    assert item.subject == "Contact [email] at [link]"


def test_history_does_not_store_indicator_explanations(monkeypatch, tmp_path):
    from app.schemas import Indicator

    path = tmp_path / "history.db"; monkeypatch.setattr(db, "DB_PATH", path)
    result = _result().model_copy(update={
        "indicators": [Indicator(code="suspicious_url_domain", severity="medium", message="Sensitive host: private.example")]
    })
    db.save_scan(_email(), result, "user-a")
    raw = path.read_bytes()
    assert b"private.example" not in raw
    assert b"suspicious_url_domain" in raw


def test_history_is_trimmed_to_fifty_per_user(monkeypatch, tmp_path):
    path = tmp_path / "history.db"; monkeypatch.setattr(db, "DB_PATH", path)
    for index in range(55): db.save_scan(_email(index), _result(), "user-a")
    assert len(db.get_history("user-a", limit=100)) == 50


def test_clearing_one_user_preserves_another(monkeypatch, tmp_path):
    path = tmp_path / "history.db"; monkeypatch.setattr(db, "DB_PATH", path)
    db.save_scan(_email(), _result(), "user-a"); db.save_scan(_email(), _result(), "user-b")
    assert db.clear_history("user-a") == 1
    assert db.get_history("user-a") == [] and len(db.get_history("user-b")) == 1


def test_database_has_privacy_indexes(monkeypatch, tmp_path):
    path = tmp_path / "history.db"; monkeypatch.setattr(db, "DB_PATH", path); db.init_db()
    with sqlite3.connect(path) as connection:
        indexes = {row[1] for row in connection.execute("PRAGMA index_list(scans)")}
    assert {"idx_scans_user_id", "idx_scans_scanned_at"}.issubset(indexes)


def test_plain_legacy_user_id_is_migrated_without_losing_history(monkeypatch, tmp_path):
    path = tmp_path / "history.db"; monkeypatch.setattr(db, "DB_PATH", path); db.init_db()
    with sqlite3.connect(path) as connection:
        connection.execute(
            """INSERT INTO scans (subject, sender, user_id, verdict, risk_score, ai_prediction,
               ai_confidence, indicator_count, indicators_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            ("Legacy", "sender", "user-a", "Low Risk", 0, "legitimate", 0.1, 0, "[]"),
        )
    db.init_db()
    assert db.get_history("user-a")[0].subject == "Legacy"
    assert b"user-a" not in path.read_bytes()
