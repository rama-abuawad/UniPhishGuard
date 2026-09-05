from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from datetime import datetime, timedelta, timezone
import hmac
import hashlib
import os
import re

from .schemas import EmailAnalysisRequest, EmailAnalysisResponse, HistoryItem


DB_PATH = Path(__file__).resolve().parents[1] / "data" / "uniphishguard.db"
HISTORY_LIMIT = int(os.getenv("HISTORY_ITEM_LIMIT", "50"))
RETENTION_DAYS = int(os.getenv("HISTORY_RETENTION_DAYS", "30"))
if HISTORY_LIMIT < 1 or HISTORY_LIMIT > 1000:
    raise RuntimeError("HISTORY_ITEM_LIMIT must be between 1 and 1000.")
if RETENTION_DAYS < 1 or RETENTION_DAYS > 3650:
    raise RuntimeError("HISTORY_RETENTION_DAYS must be between 1 and 3650.")
HMAC_SECRET = os.getenv("HISTORY_HMAC_SECRET", "local-dev-history-secret").encode("utf-8")
SQLITE_TIMEOUT_SECONDS = 5


def _connect() -> sqlite3.Connection:
    connection = sqlite3.connect(DB_PATH, timeout=SQLITE_TIMEOUT_SECONDS)
    connection.execute(f"PRAGMA busy_timeout = {SQLITE_TIMEOUT_SECONDS * 1000}")
    return connection


def init_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    with _connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scanned_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                subject TEXT NOT NULL,
                sender TEXT NOT NULL,
                user_id TEXT NOT NULL DEFAULT 'local',
                verdict TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                ai_prediction TEXT NOT NULL,
                ai_confidence REAL NOT NULL,
                indicator_count INTEGER NOT NULL,
                indicators_json TEXT NOT NULL
            )
            """
        )
        columns = {row[1] for row in conn.execute("PRAGMA table_info(scans)").fetchall()}
        if "user_id" not in columns:
            conn.execute("ALTER TABLE scans ADD COLUMN user_id TEXT NOT NULL DEFAULT 'local'")
        _migrate_user_keys(conn)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_user_id ON scans(user_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_scanned_at ON scans(scanned_at)")
        _cleanup_old_scans(conn)


def database_ready() -> bool:
    try:
        init_db()
        with _connect() as conn:
            return conn.execute("SELECT 1").fetchone() == (1,)
    except (sqlite3.Error, OSError):
        return False


def save_scan(email: EmailAnalysisRequest, result: EmailAnalysisResponse, user_id: str = "local") -> tuple[int, str]:
    init_db()

    # History does not need full messages, domains, URLs, or filenames from
    # indicator explanations. Persist only the code and severity.
    indicators = [{"code": indicator.code, "severity": indicator.severity} for indicator in result.indicators]
    user_key = _user_key(user_id)
    with _connect() as conn:
        cursor = conn.execute(
            """
            INSERT INTO scans (
                subject,
                sender,
                user_id,
                verdict,
                risk_score,
                ai_prediction,
                ai_confidence,
                indicator_count,
                indicators_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                _minimize_subject(email.subject),
                _pseudonymize_sender(str(email.sender.email)),
                user_key,
                result.verdict,
                result.risk_score,
                result.ai_prediction,
                result.ai_confidence,
                len(result.indicators),
                json.dumps(indicators),
            ),
        )
        scan_id = int(cursor.lastrowid)
        scanned_at = conn.execute(
            "SELECT scanned_at FROM scans WHERE id = ?",
            (scan_id,),
        ).fetchone()[0]

        _trim_user_history(conn, user_key)

    return scan_id, scanned_at


def get_history(user_id: str = "local", limit: int = 10) -> list[HistoryItem]:
    init_db()
    limit = min(max(limit, 1), HISTORY_LIMIT)

    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT id, scanned_at, subject, sender, verdict, risk_score, indicator_count
            FROM scans
            WHERE user_id = ?
            ORDER BY id DESC
            LIMIT ?
            """,
            (_user_key(user_id), limit),
        ).fetchall()

    return [
        HistoryItem(
            scan_id=row[0],
            scanned_at=row[1],
            subject=row[2],
            sender=row[3],
            verdict=row[4],
            risk_score=row[5],
            indicator_count=row[6],
        )
        for row in rows
    ]


def clear_history(user_id: str = "local") -> int:
    init_db()
    with _connect() as conn:
        cursor = conn.execute("DELETE FROM scans WHERE user_id = ?", (_user_key(user_id),))
        return cursor.rowcount


def _minimize_subject(subject: str) -> str:
    subject = re.sub(r"[\x00-\x1f\x7f]+", " ", (subject or "")).strip()
    subject = re.sub(r"https?://\S+", "[link]", subject, flags=re.IGNORECASE)
    subject = re.sub(r"\b[^\s@]+@[^\s@]+\b", "[email]", subject)
    subject = re.sub(r"\s+", " ", subject)
    return subject[:120] if subject else "(No subject)"


def _pseudonymize_sender(sender: str) -> str:
    sender = (sender or "").strip()
    if "@" not in sender:
        return _hmac_value(sender)
    _, domain = sender.rsplit("@", 1)
    return f"{_hmac_value(sender)}@{domain[:100]}"


def _hmac_value(value: str) -> str:
    return hmac.new(HMAC_SECRET, value.lower().encode("utf-8"), hashlib.sha256).hexdigest()[:12]


def _user_key(user_id: str) -> str:
    normalized = (user_id or "local")[:160]
    return f"u_{_hmac_value(f'user:{normalized}')}"


def _migrate_user_keys(conn: sqlite3.Connection) -> None:
    for (stored_user,) in conn.execute("SELECT DISTINCT user_id FROM scans").fetchall():
        if stored_user.startswith("u_"):
            continue
        # Early development builds briefly used the bare 12-character digest.
        migrated = f"u_{stored_user}" if re.fullmatch(r"[0-9a-f]{12}", stored_user) else _user_key(stored_user)
        conn.execute("UPDATE scans SET user_id = ? WHERE user_id = ?", (migrated, stored_user))


def _cleanup_old_scans(conn: sqlite3.Connection) -> None:
    cutoff = datetime.now(timezone.utc) - timedelta(days=RETENTION_DAYS)
    conn.execute("DELETE FROM scans WHERE scanned_at < ?", (cutoff.strftime("%Y-%m-%d %H:%M:%S"),))


def _trim_user_history(conn: sqlite3.Connection, user_key: str) -> None:
    conn.execute(
        """
        DELETE FROM scans
        WHERE user_id = ?
          AND id NOT IN (
            SELECT id FROM scans
            WHERE user_id = ?
            ORDER BY id DESC
            LIMIT ?
          )
        """,
        (user_key, user_key, HISTORY_LIMIT),
    )
