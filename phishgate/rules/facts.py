"""Combine the three rule modules into the typed `Facts` the verifier compares against."""
from __future__ import annotations

from email.message import EmailMessage

from ..schemas.verdict import Facts
from .attachment_rules import check_attachments
from .header_rules import check_headers
from .url_rules import check_urls


def rule_summary(msg: EmailMessage) -> dict:
    """Loose dict for the analysis agent's prompt (untrusted-zone view)."""
    return {"headers": check_headers(msg), "urls": check_urls(msg), "attachments": check_attachments(msg)}


def compute_facts(msg: EmailMessage) -> Facts:
    """Typed facts for the verifier (control-zone view). Recomputed, never reused from the prompt."""
    h, u, a = check_headers(msg), check_urls(msg), check_attachments(msg)
    return Facts(
        sender_auth=h["sender_auth"],
        suspicious_links=u["suspicious_links"],
        dangerous_attachment=a["dangerous_attachment"],
        from_domain=h["from_domain"],
        link_count=u["link_count"],
        attachment_count=a["attachment_count"],
        reply_to_mismatch=h["reply_to_mismatch"],
        lookalike_sender=h["lookalike_sender"],
        from_address=h["from_address"],
        message_id=h["message_id"],
    )
