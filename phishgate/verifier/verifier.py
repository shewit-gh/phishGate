"""Step 3: the verifier. Plain code, not AI. Seam S2, defence layer 3.

Rules (proposal sections 1 and 4):
  * the verdict must have exactly the allowed fields (pydantic, extra=forbid)
  * facts are recomputed from the ORIGINAL .eml, never taken from the model
  * any contradiction between verdict and facts -> HOLD, case stops
  * a benign label with a soft indicator (Reply-To on another domain, sender
    domain imitating ours) or with confidence under MIN_BENIGN_CONFIDENCE -> HOLD.
    Only benign is checked this way: closing a case is the one outcome nobody
    looks at again, so it is the one that must not be talked into.
  * suspicious / phishing -> to_analyst ; benign and consistent -> closed

Seam test S2 (tests/test_seam_s2.py): a well-formed verdict whose claimed facts
do not match the headers must become HOLD.
"""
from __future__ import annotations

from ..rules.facts import compute_facts
from ..schemas.verdict import CaseStatus, CheckedVerdict, Facts, Label, ReasonCode, Verdict, label_from_reasons


MIN_BENIGN_CONFIDENCE = 0.6   # below this a "benign" is not sure enough to close a case unseen


def _contradictions(verdict: Verdict, facts: Facts) -> list[str]:
    out = []
    auth_failed = facts.sender_auth == "fail"
    if verdict.sender_auth_failed != auth_failed:
        out.append(f"sender_auth_failed claimed {verdict.sender_auth_failed}, facts say {facts.sender_auth}")
    if verdict.suspicious_links != facts.suspicious_links:
        out.append(f"suspicious_links claimed {verdict.suspicious_links}, facts say {facts.suspicious_links}")
    if verdict.dangerous_attachment != facts.dangerous_attachment:
        out.append(f"dangerous_attachment claimed {verdict.dangerous_attachment}, facts say {facts.dangerous_attachment}")
    if verdict.label == Label.BENIGN and (auth_failed or facts.suspicious_links or facts.dangerous_attachment):
        out.append("label benign but a hard indicator is present")
    if verdict.label == Label.BENIGN:
        if facts.reply_to_mismatch:
            out.append("label benign but Reply-To points to another domain")
        if facts.lookalike_sender:
            out.append("label benign but the sender domain imitates the organisation")
        if verdict.confidence < MIN_BENIGN_CONFIDENCE:
            out.append(f"label benign with confidence below {MIN_BENIGN_CONFIDENCE}")

    # The verdict must agree with its own reasons (docs/labels.md). Only the benign
    # direction is enforced: closing a case unseen is the outcome that must not be
    # talked into.
    if verdict.label == Label.BENIGN and label_from_reasons(verdict.reasons) != Label.BENIGN:
        out.append("label benign but the reasons list an indicator")

    # A reason that names a hard fact must match the claim about that fact.
    claims = {ReasonCode.SENDER_AUTH_FAIL: verdict.sender_auth_failed,
              ReasonCode.SUSPICIOUS_LINK: verdict.suspicious_links,
              ReasonCode.DANGEROUS_ATTACHMENT: verdict.dangerous_attachment}
    for code, claimed in claims.items():
        if code in verdict.reasons and not claimed:
            out.append(f"reason {code.value} given but the claim says False")

    return out


def verify(case_id: str, file_sha256: str, msg, verdict: Verdict) -> CheckedVerdict:
    facts = compute_facts(msg)
    problems = _contradictions(verdict, facts)
    if problems:
        status, reason = CaseStatus.HOLD, "; ".join(problems)
    elif verdict.label == Label.BENIGN:
        status, reason = CaseStatus.CLOSED, None
    else:
        status, reason = CaseStatus.TO_ANALYST, None
    return CheckedVerdict(case_id=case_id, file_sha256=file_sha256, verdict=verdict,
                          facts=facts, status=status, hold_reason=reason)
