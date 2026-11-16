"""WORKSPACE: one SQLite file plus outbox/.

Table `corpus` = metadata index of the synthetic mails (sender, recipient, time,
quarantine flag). No subject, no body: search_sender can only ever return what
this table holds.
Table `queue`  = pending message drafts, bulk-quarantine approvals and HOLD
cases waiting for a manual look.
`decide()` is the analyst's click: an approved message becomes a text file in
outbox/. Nothing is ever sent.

Files (all under the workspace root, all git-ignored):
    corpus/<key>.eml       working copy of each loaded mail (see corpus.py)
    quarantine/<key>.eml   the same file while the mail is quarantined
`<key>` is a hash of the message id, so attacker-chosen ids never become paths.
"""
from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
import time
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS corpus (
    message_id TEXT PRIMARY KEY,
    sender TEXT NOT NULL,
    recipient TEXT NOT NULL,
    ts REAL NOT NULL,
    quarantined INTEGER NOT NULL DEFAULT 0,
    quarantined_by_case TEXT
);
CREATE TABLE IF NOT EXISTS queue (
    item_id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,              -- 'message' | 'bulk_quarantine' | 'hold_review'
    case_id TEXT NOT NULL,
    payload TEXT NOT NULL,           -- JSON
    created REAL NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',   -- pending | approved | rejected
    decided REAL
);
"""


def _new_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(4)}"


class Workspace:
    def __init__(self, root: Path):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.outbox = self.root / "outbox"
        self.corpus_dir = self.root / "corpus"
        self.quarantine_dir = self.root / "quarantine"
        self.db = sqlite3.connect(self.root / "workspace.sqlite3")
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)

    # ---- corpus -----------------------------------------------------------------
    def add_message(self, message_id: str, sender: str, recipient: str, ts: float | None = None) -> None:
        self.db.execute("INSERT OR REPLACE INTO corpus (message_id, sender, recipient, ts) VALUES (?,?,?,?)",
                        (message_id, sender.lower(), recipient.lower(), ts if ts is not None else time.time()))
        self.db.commit()

    def search_sender(self, sender_address: str) -> list[dict]:
        rows = self.db.execute("SELECT sender, recipient, ts FROM corpus WHERE sender = ? ORDER BY ts",
                               (sender_address.lower(),))
        return [dict(r) for r in rows]

    def known_message_ids(self, message_ids: list[str]) -> set[str]:
        """The subset of `message_ids` that exists in the corpus."""
        known = set()
        for mid in message_ids:
            if self.db.execute("SELECT 1 FROM corpus WHERE message_id = ?", (mid,)).fetchone():
                known.add(mid)
        return known

    def senders_of(self, message_ids: list[str]) -> dict[str, str]:
        """message id -> sender address, for the ids that exist."""
        out = {}
        for mid in message_ids:
            r = self.db.execute("SELECT sender FROM corpus WHERE message_id = ?", (mid,)).fetchone()
            if r:
                out[mid] = r[0]
        return out

    @staticmethod
    def file_key(message_id: str) -> str:
        """File name for a message's working copy. A hash, never the id itself."""
        return hashlib.sha256(message_id.encode("utf-8")).hexdigest()[:24] + ".eml"

    def set_quarantine(self, message_ids: list[str], flag: bool, case_id: str) -> list[str]:
        """Set or clear the flag and move the working copy between corpus/ and quarantine/.

        Returns the ids that exist in the corpus (unknown ids are ignored; the gate
        refuses them before this is called). The stored originals are never touched.
        """
        changed = []
        src_dir, dst_dir = (self.corpus_dir, self.quarantine_dir) if flag else (self.quarantine_dir, self.corpus_dir)
        for mid in message_ids:
            cur = self.db.execute("UPDATE corpus SET quarantined = ?, quarantined_by_case = ? WHERE message_id = ?",
                                  (int(flag), case_id if flag else None, mid))
            if cur.rowcount:
                changed.append(mid)
                src = src_dir / self.file_key(mid)
                if src.exists():
                    dst_dir.mkdir(exist_ok=True)
                    src.replace(dst_dir / src.name)
        self.db.commit()
        return changed

    def quarantined_ids(self) -> list[str]:
        return [r[0] for r in self.db.execute("SELECT message_id FROM corpus WHERE quarantined = 1 ORDER BY ts")]

    # ---- analyst queue ----------------------------------------------------------
    def _enqueue(self, prefix: str, kind: str, case_id: str, payload: dict) -> str:
        item_id = _new_id(prefix)
        self.db.execute("INSERT INTO queue (item_id, kind, case_id, payload, created) VALUES (?,?,?,?,?)",
                        (item_id, kind, case_id, json.dumps(payload, ensure_ascii=False), time.time()))
        self.db.commit()
        return item_id

    def queue_message(self, case_id: str, template_id: str, subject: str, body: str) -> str:
        return self._enqueue("msg", "message", case_id,
                             {"template_id": template_id, "subject": subject, "body": body})

    def queue_bulk_quarantine(self, case_id: str, message_ids: list[str]) -> str:
        return self._enqueue("bulk", "bulk_quarantine", case_id, {"message_ids": list(message_ids)})

    def queue_hold_review(self, case_id: str, hold_reason: str) -> str:
        """A HOLD case waits here for the analyst. `hold_reason` is written by code, never by a model."""
        return self._enqueue("hold", "hold_review", case_id, {"hold_reason": hold_reason})

    def notify_count_last_hour(self) -> int:
        """Messages queued in the last hour, whatever their later decision (the rate limit counts attempts)."""
        row = self.db.execute("SELECT COUNT(*) FROM queue WHERE kind = 'message' AND created >= ?",
                              (time.time() - 3600,)).fetchone()
        return row[0]

    def pending(self) -> list[dict]:
        rows = self.db.execute("SELECT * FROM queue WHERE status = 'pending' ORDER BY created")
        return [{**dict(r), "payload": json.loads(r["payload"])} for r in rows]

    def decide(self, item_id: str, approve: bool) -> dict | None:
        """The analyst's click. Returns None if the item is unknown or already decided."""
        r = self.db.execute("SELECT * FROM queue WHERE item_id = ? AND status = 'pending'", (item_id,)).fetchone()
        if r is None:
            return None
        payload = json.loads(r["payload"])
        status = "approved" if approve else "rejected"
        self.db.execute("UPDATE queue SET status = ?, decided = ? WHERE item_id = ?", (status, time.time(), item_id))
        self.db.commit()
        out = {"item_id": item_id, "kind": r["kind"], "case_id": r["case_id"], "status": status}
        if approve and r["kind"] == "message":
            self.outbox.mkdir(exist_ok=True)
            path = self.outbox / f"{item_id}.txt"
            path.write_text(f"Subject: {payload['subject']}\n\n{payload['body']}\n", encoding="utf-8")
            out["outbox_file"] = str(path)
        elif approve and r["kind"] == "bulk_quarantine":
            out["quarantined"] = self.set_quarantine(payload["message_ids"], True, r["case_id"])
        return out
