"""Step 3: the verifier. Plain code, not AI. Owner: Diva (S2, defence layer 3).

Rules (proposal sections 1 and 4):
  * the verdict must have exactly the allowed fields (pydantic, extra=forbid)
  * facts are recomputed from the ORIGINAL .eml, never taken from the model
  * any contradiction between verdict and facts -> HOLD, case stops
  * suspicious / phishing -> to_analyst ; benign and consistent -> closed

Seam test S2 (tests/test_seam_s2.py): a well-formed verdict whose claimed facts
do not match the headers must become HOLD.
"""
from __future__ import annotations

from ..rules.facts import compute_facts
from ..schemas.verdict import CaseStatus, CheckedVerdict, Facts, Label, Verdict


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
