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
    """Verdict labels (proposal section 1). One meaning, used by the prompt, the
    verifier and the corpus labels. Mirrored in docs/labels.md.

    An *indicator* is any ReasonCode other than ``none``. A *hard indicator* is one
    plain code recomputes from the .eml: sender_auth_fail, suspicious_link,
    dangerous_attachment. Soft indicators (mismatched_reply_to, lookalike_domain)
    are recomputed too but used only to stop a benign label.

    benign      No indicator is present. Nothing for the analyst to do; closed.
    suspicious  At least one indicator, but the phishing rule is not met.
                An analyst must look; no action is proposed.
    phishing    A credible attempt to obtain credentials, money or data, or to
                deliver malware. Rule, any one of:
                  (a) sender_auth_fail AND (credential_request OR payment_request)
                  (b) lookalike_domain AND (credential_request OR payment_request)
                  (c) dangerous_attachment
                  (d) suspicious_link AND credential_request

    HOLD is not a label and the model can never choose it. It is a CaseStatus set
    by the verifier when a verdict contradicts the recomputed facts.
    """
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    PHISHING = "phishing"


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

HARD_INDICATORS = frozenset({ReasonCode.SENDER_AUTH_FAIL, ReasonCode.SUSPICIOUS_LINK,
                             ReasonCode.DANGEROUS_ATTACHMENT})
_ASKS = frozenset({ReasonCode.CREDENTIAL_REQUEST, ReasonCode.PAYMENT_REQUEST})


def label_from_reasons(reasons) -> Label:
    """The label definition as a rule (same text in Label's docstring and docs/labels.md).

    benign: no indicator. phishing: any of (a) sender_auth_fail or lookalike_domain
    with a credential/payment request, (b) dangerous_attachment, (c) suspicious_link
    with a credential request. Otherwise suspicious.
    """
    r = set(reasons) - {ReasonCode.NONE}
    if not r:
        return Label.BENIGN
    if ReasonCode.DANGEROUS_ATTACHMENT in r:
        return Label.PHISHING
    if r & {ReasonCode.SENDER_AUTH_FAIL, ReasonCode.LOOKALIKE_DOMAIN} and r & _ASKS:
        return Label.PHISHING
    if ReasonCode.SUSPICIOUS_LINK in r and ReasonCode.CREDENTIAL_REQUEST in r:
        return Label.PHISHING
    return Label.SUSPICIOUS

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
    """Set by the verifier (plain code), never by a model.

    closed      Label benign, every claim agrees with the facts, no indicator,
                confidence at or above the floor (0.6).
    to_analyst  Label suspicious or phishing and the claims agree with the facts.
                An analyst reviews; the action agent may propose actions.
    hold        A claim contradicts the recomputed facts, or the label is benign
                while any indicator is present or confidence is under the floor,
                or the model gave no valid output. The case stops: no action
                agent, no tool call. ``hold_reason`` says why.
    """
    CLOSED = "closed"
    TO_ANALYST = "to_analyst"
    HOLD = "hold"

class CheckedVerdict(BaseModel):
    """What the action agent receives. Contains no e-mail text."""
    model_config = ConfigDict(extra="forbid")

    case_id: str
    file_sha256: str
    verdict: Verdict
    facts: Facts
    status: CaseStatus
    hold_reason: str | None = None  # written by verifier code, never by a model
