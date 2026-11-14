"""search_sender(addr): other mails from the same sender. Returns sender, recipient, time ONLY.

No subject, no body: this is what stops exfiltration (T5) through search.
"""
from __future__ import annotations


def search(ws, sender_address: str) -> list[dict]:
    return ws.search_sender(sender_address)
