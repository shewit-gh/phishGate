"""URL rules: IP-literal hosts, punycode, look-alike domains, text/href mismatch. Owner: Shewit.

TODO: look-alike detection against the synthetic organisation's domains
(data/corpus/org_domains.txt), confusable characters, href vs anchor text.
"""
from __future__ import annotations

import re
from email.message import EmailMessage
from urllib.parse import urlparse

_URL_RE = re.compile(r"""https?://[^\s<>"')\]]+""", re.I)
_IP_HOST_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _bodies(msg: EmailMessage):
    for part in msg.walk():
        if part.get_content_type() in ("text/plain", "text/html") and not part.is_attachment():
            try:
                yield part.get_content()
            except Exception:  # malformed part: skip, never crash the rule
                continue


def check_urls(msg: EmailMessage) -> dict:
    urls: list[str] = []
    for text in _bodies(msg):
        urls.extend(_URL_RE.findall(text))
    flagged = []
    for u in urls:
        host = (urlparse(u).hostname or "").lower()
        reasons = []
        if _IP_HOST_RE.match(host):
            reasons.append("ip_literal")
        if host.startswith("xn--") or ".xn--" in host:
            reasons.append("punycode")
        if reasons:
            flagged.append({"url": u[:200], "reasons": reasons})
    return {"link_count": len(urls), "suspicious_links": bool(flagged), "flagged": flagged}
