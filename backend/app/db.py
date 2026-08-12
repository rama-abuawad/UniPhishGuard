from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from datetime import datetime, timedelta, timezone
import hmac
import hashlib
import os

from .schemas import EmailAnalysisRequest, EmailAnalysisResponse, HistoryItem


DB_PATH = Path(__file__).resolve().parents[1] / "data" / "uniphishguard.db"
HISTORY_LIMIT = int(os.getenv("HISTORY_ITEM_LIMIT", "50"))
RETENTION_DAYS = int(os.getenv("HISTORY_RETENTION_DAYS", "30"))
if HISTORY_LIMIT < 1 or HISTORY_LIMIT > 1000:
    raise RuntimeError("HISTORY_ITEM_LIMIT must be between 1 and 1000.")
if RETENTION_DAYS < 1 or RETENTION_DAYS > 3650:
    raise RuntimeError("HISTORY_RETENTION_DAYS must be between 1 and 3650.")
HMAC_SECRET = os.getenv("HISTORY_HMAC_SECRET", "local-dev-history-secret").encode("utf-8")


def init_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(DB_PATH) as conn:
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
        conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_user_id ON scans(user_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_scanned_at ON scans(scanned_at)")
        _cleanup_old_scans(conn)


def database_ready() -> bool:
    try:
        init_db()
        with sqlite3.connect(DB_PATH) as conn:
            return conn.execute("SELECT 1").fetchone() == (1,)
    except sqlite3.Error:
        return False


def save_scan(email: EmailAnalysisRequest, result: EmailAnalysisResponse, user_id: str = "local") -> tuple[int, str]:
    init_db()

    indicators = [indicator.model_dump() for indicator in result.indicators]
    with sqlite3.connect(DB_PATH) as conn:
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
                _redact_subject(email.subject),
                _pseudonymize_sender(str(email.sender.email)),
                user_id[:160],
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

        _trim_user_history(conn, user_id)

    return scan_id, scanned_at


def get_history(user_id: str = "local", limit: int = 10) -> list[HistoryItem]:
    init_db()
    limit = min(max(limit, 1), HISTORY_LIMIT)

    with sqlite3.connect(DB_PATH) as conn:
        rows = conn.execute(
            """
            SELECT id, scanned_at, subject, sender, verdict, risk_score, indicator_count
            FROM scans
            WHERE user_id = ?
            ORDER BY id DESC
            LIMIT ?
            """,
            (user_id[:160], limit),
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
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute("DELETE FROM scans WHERE user_id = ?", (user_id[:160],))
        return cursor.rowcount


def _redact_subject(subject: str) -> str:
    subject = (subject or "").strip()
    return subject[:120] if subject else "(No subject)"


def _pseudonymize_sender(sender: str) -> str:
    sender = (sender or "").strip()
    if "@" not in sender:
        return _hmac_value(sender)
    _, domain = sender.rsplit("@", 1)
    return f"{_hmac_value(sender)}@{domain[:100]}"


def _hmac_value(value: str) -> str:
    return hmac.new(HMAC_SECRET, value.lower().encode("utf-8"), hashlib.sha256).hexdigest()[:12]


def _cleanup_old_scans(conn: sqlite3.Connection) -> None:
    cutoff = datetime.now(timezone.utc) - timedelta(days=RETENTION_DAYS)
    conn.execute("DELETE FROM scans WHERE scanned_at < ?", (cutoff.strftime("%Y-%m-%d %H:%M:%S"),))


def _trim_user_history(conn: sqlite3.Connection, user_id: str) -> None:
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
        (user_id[:160], user_id[:160], HISTORY_LIMIT),
    )
