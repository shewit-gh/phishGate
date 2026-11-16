"""Seam S2 contract: what crosses TRUST BOUNDARY 1.

Only a `Verdict` (fixed fields, closed vocabularies, no free text) may leave the
untrusted zone. The verifier turns it into a `CheckedVerdict`. Nothing else
from the e-mail side is ever passed on.

Changing a field here changes S1's prompt and S3's input, so
announce changes to the whole team.
"""
from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class Label(str, Enum):
    """The three verdict labels defined in proposal §1."""
    BENIGN = "benign"          # no phishing indicator, nothing to do
    SUSPICIOUS = "suspicious"  # at least one indicator, analyst must look
    PHISHING = "phishing"      # credible attempt at credentials, money, data or malware


class ReasonCode(str, Enum):
    """Closed list of reasons. The model picks from these; it cannot write prose."""
    SENDER_AUTH_FAIL = "sender_auth_fail"      # SPF / DKIM / DMARC failed
    LOOKALIKE_DOMAIN = "lookalike_domain"
    URGENT_LANGUAGE = "urgent_language"
    CREDENTIAL_REQUEST = "credential_request"
    PAYMENT_REQUEST = "payment_request"
    SUSPICIOUS_LINK = "suspicious_link"        # IP literal, punycode, mismatched text/href
    DANGEROUS_ATTACHMENT = "dangerous_attachment"  # macro, executable, mismatched type
    MISMATCHED_REPLY_TO = "mismatched_reply_to"
    NONE = "none"


class Verdict(BaseModel):
    """Exactly what the analysis agent may output. Unknown fields are rejected."""
    model_config = ConfigDict(extra="forbid")

    label: Label
    reasons: list[ReasonCode] = Field(default_factory=list, max_length=6)
    # The model's own claims about the three hard facts. The verifier recomputes
    # them from the raw .eml and any disagreement becomes HOLD.
    sender_auth_failed: bool
    suspicious_links: bool
    dangerous_attachment: bool
    confidence: float = Field(ge=0.0, le=1.0)


class Facts(BaseModel):
    """Hard facts recomputed by plain code from the original .eml (never from the model)."""
    model_config = ConfigDict(extra="forbid")

    sender_auth: Literal["pass", "fail", "none"]
    suspicious_links: bool
    dangerous_attachment: bool
    from_domain: str = ""
    link_count: int = 0
    attachment_count: int = 0
    # Soft indicators. Not claimed by the model; the verifier uses them to stop a "benign" label.
    reply_to_mismatch: bool = False
    lookalike_sender: bool = False
    # What the action agent may act on. Shape-checked by rules/header_rules.py, '' if unusable.
    from_address: str = ""
    message_id: str = ""


class CaseStatus(str, Enum):
    CLOSED = "closed"            # confirmed benign, nothing to do
    TO_ANALYST = "to_analyst"    # suspicious or phishing: analyst reviews, action agent may propose
    HOLD = "hold"                # verdict contradicts facts; case stops here


class CheckedVerdict(BaseModel):
    """What the action agent receives. Contains no e-mail text."""
    model_config = ConfigDict(extra="forbid")

    case_id: str
    file_sha256: str
    verdict: Verdict
    facts: Facts
    status: CaseStatus
    hold_reason: str | None = None  # written by verifier code, never by a model
