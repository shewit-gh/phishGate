"""URL rules: IP-literal hosts, punycode, look-alike domains, text/href mismatch.

Links are collected from the raw text of every text part, so a link inside a
hidden HTML element or a comment still counts. For HTML parts the visible
anchor text is compared with the real target.
"""
from __future__ import annotations

import re
from email.message import EmailMessage
from urllib.parse import urlparse

from .domains import is_lookalike, registrable
from .html_text import html_view

_URL_RE = re.compile(r"""https?://[^\s<>"')\]]+""", re.I)
_IP_HOST_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
# Anchor text that is itself an address: "https://x.test/..", "www.x.test", or a bare "x.test".
_TEXT_URL_RE = re.compile(r"^(?:https?://|www\.)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?:[/:?#].*)?$", re.I)


def _host(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def _bodies(msg: EmailMessage):
    for part in msg.walk():
        ctype = part.get_content_type()
        if ctype in ("text/plain", "text/html") and not part.is_attachment():
            try:
                yield ctype, part.get_content()
            except Exception:  # malformed part: skip, never crash the rule
                continue


def check_urls(msg: EmailMessage) -> dict:
    urls: list[str] = []
    mismatched: list[str] = []
    hidden_text = comments = False
    for ctype, text in _bodies(msg):
        urls.extend(_URL_RE.findall(text))
        if ctype != "text/html":
            continue
        view = html_view(text)
        hidden_text, comments = hidden_text or view.hidden_text, comments or view.comments
        for href, anchor in view.links:
            shown = _TEXT_URL_RE.match(anchor.strip())
            target = _host(href)
            if shown and target and registrable(shown.group(1).lower().removeprefix("www.")) != registrable(target):
                mismatched.append(href)
    flagged = []
    for u in dict.fromkeys(urls):
        host = _host(u)
        reasons = []
        if _IP_HOST_RE.match(host):
            reasons.append("ip_literal")
        if host.startswith("xn--") or ".xn--" in host:
            reasons.append("punycode")
        if is_lookalike(host):
            reasons.append("lookalike")
        if u in mismatched:
            reasons.append("text_href_mismatch")
        if reasons:
            flagged.append({"url": u[:200], "reasons": reasons})
    return {
        "link_count": len(urls),
        "suspicious_links": bool(flagged),
        "flagged": flagged,
        "hidden_html_text": hidden_text,      # text a reader cannot see: a signal, its content is not passed on
        "html_comments": comments,
    }
