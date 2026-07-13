from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from .models import EmailAnalysisRequest, EmailAnalysisResponse, HistoryItem


DB_PATH = Path(__file__).resolve().parents[1] / "data" / "uniphishguard.db"


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
                verdict TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                ai_prediction TEXT NOT NULL,
                ai_confidence REAL NOT NULL,
                indicator_count INTEGER NOT NULL,
                indicators_json TEXT NOT NULL
            )
            """
        )


def save_scan(email: EmailAnalysisRequest, result: EmailAnalysisResponse) -> tuple[int, str]:
    init_db()

    indicators = [indicator.model_dump() for indicator in result.indicators]
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            """
            INSERT INTO scans (
                subject,
                sender,
                verdict,
                risk_score,
                ai_prediction,
                ai_confidence,
                indicator_count,
                indicators_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                email.subject[:200],
                str(email.sender.email)[:200],
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

    return scan_id, scanned_at


def get_history(limit: int = 10) -> list[HistoryItem]:
    init_db()

    with sqlite3.connect(DB_PATH) as conn:
        rows = conn.execute(
            """
            SELECT id, scanned_at, subject, sender, verdict, risk_score, indicator_count
            FROM scans
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
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
