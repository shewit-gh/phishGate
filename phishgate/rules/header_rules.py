"""Header rules: SPF / DKIM / DMARC results, Reply-To mismatch, look-alike sender.

Reads the Authentication-Results header already present in the .eml.
The container has no network, so live DMARC lookups (checkdmarc) are not
possible; record that as an accepted gap in the paper.

Every value returned here is recomputed by code from attacker-written headers.
Addresses and ids are returned only when they have a plain, expected shape;
otherwise they are returned empty, so they can be used downstream as data.
"""
from __future__ import annotations

import re
from email.message import EmailMessage
from email.utils import parseaddr

from .domains import is_lookalike, registrable

_RESULT_RE = {
    mech: re.compile(rf"\b{mech}=(pass|fail|softfail|none|neutral|temperror|permerror)", re.I)
    for mech in ("spf", "dkim", "dmarc")
}
_ADDRESS_RE = re.compile(r"^[a-z0-9._%+-]{1,64}@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$")
_MESSAGE_ID_RE = re.compile(r"^(?=.{3,120}$)[A-Za-z0-9._+-]+@[A-Za-z0-9.-]+$")


def _address(value: str) -> str:
    """Lower-cased address if it has a plain shape, else ''."""
    address = parseaddr(value)[1].strip().lower()
    return address if _ADDRESS_RE.match(address) else ""


def _domain(addr: str) -> str:
    address = parseaddr(addr)[1]
    return address.rsplit("@", 1)[-1].lower() if "@" in address else ""


def message_id(msg: EmailMessage) -> str:
    """Message-ID without angle brackets if it has a plain shape, else ''."""
    mid = str(msg.get("Message-ID", "")).strip().strip("<>").strip()
    return mid if _MESSAGE_ID_RE.match(mid) else ""


def check_headers(msg: EmailMessage) -> dict:
    auth = " ".join(str(v) for v in msg.get_all("Authentication-Results", []))
    results = {}
    for mech, rx in _RESULT_RE.items():
        m = rx.search(auth)
        results[mech] = m.group(1).lower() if m else "none"
    # softfail means "probably not authorised". It counts as a failure unless DMARC passed.
    soft = results["dmarc"] != "pass" and any(v == "softfail" for v in results.values())
    if any(v == "fail" for v in results.values()) or soft:
        sender_auth = "fail"
    elif any(v == "pass" for v in results.values()):
        sender_auth = "pass"
    else:
        sender_auth = "none"
    from_domain = _domain(str(msg.get("From", "")))
    reply_domain = _domain(str(msg.get("Reply-To", "")))
    return {
        "sender_auth": sender_auth,
        "mechanisms": results,
        "from_domain": from_domain,
        "from_address": _address(str(msg.get("From", ""))),
        "message_id": message_id(msg),
        # Compared by registrable domain, so news@mail.x.test replying to x.test is not a mismatch.
        "reply_to_mismatch": bool(reply_domain) and registrable(reply_domain) != registrable(from_domain),
        "lookalike_sender": is_lookalike(from_domain),
    }
