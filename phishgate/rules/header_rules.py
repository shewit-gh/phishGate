"""Header rules: SPF / DKIM / DMARC results, Reply-To mismatch. Owner: Shewit.

Skeleton reads the Authentication-Results header already present in the .eml.
The container has no network, so live DMARC lookups (checkdmarc) are not
possible; record that as an accepted gap in the paper.
"""
from __future__ import annotations

import re
from email.message import EmailMessage
from email.utils import parseaddr

_RESULT_RE = {
    mech: re.compile(rf"\b{mech}=(pass|fail|softfail|none|neutral|temperror|permerror)", re.I)
    for mech in ("spf", "dkim", "dmarc")
}


def _domain(addr: str) -> str:
    address = parseaddr(addr)[1]
    return address.rsplit("@", 1)[-1].lower() if "@" in address else ""


def check_headers(msg: EmailMessage) -> dict:
    auth = " ".join(str(v) for v in msg.get_all("Authentication-Results", []))
    results = {}
    for mech, rx in _RESULT_RE.items():
        m = rx.search(auth)
        results[mech] = m.group(1).lower() if m else "none"
    if any(v == "fail" for v in results.values()):
        sender_auth = "fail"
    elif any(v == "pass" for v in results.values()):
        sender_auth = "pass"
    else:
        sender_auth = "none"
    from_domain = _domain(msg.get("From", ""))
    reply_domain = _domain(msg.get("Reply-To", ""))
    return {
        "sender_auth": sender_auth,
        "mechanisms": results,
        "from_domain": from_domain,
        "reply_to_mismatch": bool(reply_domain) and reply_domain != from_domain,
    }
