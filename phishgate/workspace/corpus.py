"""Corpus loader: index a folder of synthetic .eml files into the workspace.

For every mail it stores ONLY sender, recipient and time in the `corpus` table
(this is all `search_sender` can ever return) and puts a working copy in
`<workspace>/corpus/`. Quarantine moves that copy; the source folder is never
modified.

Everything read here is attacker-written (Message-ID, From, To, Date). It is
used as data only: ids go into SQL as parameters and file names are hashes.
"""
from __future__ import annotations

import email
import hashlib
from email import policy
from email.utils import parseaddr, parsedate_to_datetime
from pathlib import Path

from ..rules.header_rules import message_id as _header_message_id
from .db import Workspace

MAX_EML_BYTES = 2 * 1024 * 1024   # same cap as intake


def message_id_of(raw: bytes) -> str:
    """Message-ID without angle brackets; a content hash if the header is missing or unusable."""
    msg = email.message_from_bytes(raw, policy=policy.default)
    return _header_message_id(msg) or "sha256:" + hashlib.sha256(raw).hexdigest()[:32]


def _timestamp(msg) -> float | None:
    try:
        return parsedate_to_datetime(str(msg.get("Date", ""))).timestamp()
    except (TypeError, ValueError):
        return None


def index_message(ws: Workspace, raw: bytes, keep_existing: bool = False) -> str | None:
    """Index one mail and store its working copy. Returns its id, or None if it cannot be indexed.

    With `keep_existing`, a mail that is already in the corpus is left as it is
    (so a re-reported mail does not lose its quarantine flag).
    """
    if len(raw) > MAX_EML_BYTES:
        return None
    msg = email.message_from_bytes(raw, policy=policy.default)
    sender = parseaddr(str(msg.get("From", "")))[1]
    recipient = parseaddr(str(msg.get("To", "")))[1]
    if "@" not in sender:
        return None
    mid = message_id_of(raw)
    if keep_existing and ws.known_message_ids([mid]):
        return mid
    ws.add_message(mid, sender, recipient, _timestamp(msg))
    ws.corpus_dir.mkdir(exist_ok=True)
    (ws.corpus_dir / ws.file_key(mid)).write_bytes(raw)
    return mid


def load_corpus(ws: Workspace, folder: Path) -> dict:
    """Index every .eml under `folder`. Returns {"loaded": n, "skipped": [file names]}."""
    loaded, skipped = 0, []
    for path in sorted(Path(folder).rglob("*.eml")):
        if index_message(ws, path.read_bytes()) is None:
            skipped.append(path.name)
        else:
            loaded += 1
    return {"loaded": loaded, "skipped": skipped}
