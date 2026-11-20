"""AUDIT LOG: sqlite, append-only, SHA-256 hash chain. Defence layer 6.

Every prompt, tool call, verdict, gate decision and approval is one row. Each
row carries the hash of the previous row, so deleting or editing a row breaks
the chain. `verify_chain()` is what the paper's "tamper-evident" claim rests on.
Payloads are stored as JSON with structured escaping, so a filename or body
string from an attacker cannot forge a row boundary.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from pathlib import Path

GENESIS = "0" * 64

# Rows that mean "something happened in the world". Each must trace to a verdict_checked row.
ACTION_EVENTS = ("notify_queued", "quarantine_queued", "quarantine_executed", "search_sender_executed")

SCHEMA = """
CREATE TABLE IF NOT EXISTS audit (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    event TEXT NOT NULL,
    case_id TEXT,
    payload TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    row_hash TEXT NOT NULL
);
"""


def _row_hash(ts: float, event: str, case_id: str | None, payload: str, prev_hash: str) -> str:
    material = json.dumps([ts, event, case_id, payload, prev_hash], ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


class AuditLog:
    def __init__(self, path: Path):
        self.db = sqlite3.connect(Path(path))
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)

    def _last_hash(self) -> str:
        row = self.db.execute("SELECT row_hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
        return row[0] if row else GENESIS

    def append(self, event: str, case_id: str | None, payload: dict) -> int:
        ts = time.time()
        payload_json = json.dumps(payload, ensure_ascii=False, default=str, separators=(",", ":"))
        prev = self._last_hash()
        h = _row_hash(ts, event, case_id, payload_json, prev)
        cur = self.db.execute("INSERT INTO audit (ts, event, case_id, payload, prev_hash, row_hash) VALUES (?,?,?,?,?,?)",
                              (ts, event, case_id, payload_json, prev, h))
        self.db.commit()
        return cur.lastrowid

    def rows(self, case_id: str | None = None) -> list[dict]:
        q = "SELECT * FROM audit" + (" WHERE case_id = ?" if case_id else "") + " ORDER BY seq"
        return [dict(r) for r in self.db.execute(q, (case_id,) if case_id else ())]

    def verify_chain(self) -> tuple[bool, int | None]:
        """Return (ok, first_bad_seq). Recomputes every hash from the genesis value."""
        prev = GENESIS
        for r in self.rows():
            if r["prev_hash"] != prev:
                return False, r["seq"]
            if _row_hash(r["ts"], r["event"], r["case_id"], r["payload"], prev) != r["row_hash"]:
                return False, r["seq"]
            prev = r["row_hash"]
        return True, None

    def untraced_actions(self) -> list[int]:
        """Seq of every action row whose case has no earlier verdict_checked row.
        Empty list = 100 % of actions trace back to a checked verdict (proposal section 5)."""
        checked_cases: set[str] = set()
        bad = []
        for r in self.rows():
            if r["event"] == "verdict_checked":
                checked_cases.add(r["case_id"])
            elif r["event"] in ACTION_EVENTS and r["case_id"] not in checked_cases:
                bad.append(r["seq"])
        return bad
