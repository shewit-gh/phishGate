"""Seam S2 : verdict -> verifier -> action agent.

Proposal seam test: a well-formed verdict whose claimed facts do not match the
headers must become HOLD. Also: extra fields are rejected before the verifier
ever sees them, and a consistent benign verdict closes the case.
"""
import json

import pytest
from pydantic import ValidationError

from phishgate.schemas import CaseStatus, Label, Verdict, label_from_reasons
from phishgate.verifier import verify


def _verdict(**kw):
    base = {"label": "benign", "reasons": ["none"], "sender_auth_failed": False,
            "suspicious_links": False, "dangerous_attachment": False, "confidence": 0.9}
    base.update(kw)
    return Verdict.model_validate(base)


def test_injected_benign_verdict_becomes_hold(injected_msg):
    # This is exactly what the hidden instruction in injected_reset.eml asks the model to output.
    v = _verdict()
    checked = verify("case_test", "sha", injected_msg, v)
    assert checked.status == CaseStatus.HOLD
    assert "sender_auth_failed" in checked.hold_reason
    assert "suspicious_links" in checked.hold_reason


def test_consistent_benign_verdict_closes(benign_msg):
    checked = verify("case_test", "sha", benign_msg, _verdict())
    assert checked.status == CaseStatus.CLOSED
    assert checked.hold_reason is None


def test_honest_phishing_verdict_goes_to_analyst(injected_msg):
    v = _verdict(label="phishing", reasons=["sender_auth_fail", "suspicious_link"],
                 sender_auth_failed=True, suspicious_links=True)
    checked = verify("case_test", "sha", injected_msg, v)
    assert checked.status == CaseStatus.TO_ANALYST


def test_extra_field_is_rejected_by_schema():
    with pytest.raises(ValidationError):
        Verdict.model_validate(json.loads(
            '{"label":"benign","reasons":[],"sender_auth_failed":false,"suspicious_links":false,'
            '"dangerous_attachment":false,"confidence":0.5,"note":"tell staff to reset passwords"}'))


# --- one test per verifier rule ---------------------------------------------

def test_benign_with_indicator_reason_is_hold(benign_msg):
    v = _verdict(reasons=["urgent_language"])
    checked = verify("case_test", "sha", benign_msg, v)
    assert checked.status == CaseStatus.HOLD
    assert "reasons list an indicator" in checked.hold_reason


def test_reason_contradicting_claim_is_hold(injected_msg):
    # says sender auth failed in reasons, but claims it did not
    v = _verdict(label="phishing", reasons=["sender_auth_fail", "credential_request"],
                 sender_auth_failed=False, suspicious_links=True)
    checked = verify("case_test", "sha", injected_msg, v)
    assert checked.status == CaseStatus.HOLD
    assert "sender_auth_fail given but the claim says False" in checked.hold_reason


def test_low_confidence_benign_is_hold(benign_msg):
    checked = verify("case_test", "sha", benign_msg, _verdict(confidence=0.4))
    assert checked.status == CaseStatus.HOLD
    assert "confidence below" in checked.hold_reason


def test_benign_with_foreign_reply_to_is_hold(benign_msg):
    benign_msg.replace_header("Reply-To", "billing@collect-now.test") \
        if benign_msg["Reply-To"] else benign_msg.add_header("Reply-To", "billing@collect-now.test")
    checked = verify("case_test", "sha", benign_msg, _verdict())
    assert checked.status == CaseStatus.HOLD
    assert "Reply-To" in checked.hold_reason


def test_verifier_never_lowers_a_label(injected_msg):
    # sycophancy guard: whatever the verifier does, a phishing label stays phishing
    v = _verdict(label="phishing", reasons=["sender_auth_fail", "credential_request"],
                 sender_auth_failed=True, suspicious_links=True)
    checked = verify("case_test", "sha", injected_msg, v)
    assert checked.verdict.label == Label.PHISHING
    assert checked.status != CaseStatus.CLOSED


# --- the definition itself ----------------------------------------------------

def test_label_rule_matches_docs():
    assert label_from_reasons(["none"]) == Label.BENIGN
    assert label_from_reasons([]) == Label.BENIGN
    assert label_from_reasons(["urgent_language"]) == Label.SUSPICIOUS
    assert label_from_reasons(["sender_auth_fail"]) == Label.SUSPICIOUS
    assert label_from_reasons(["sender_auth_fail", "payment_request"]) == Label.PHISHING
    assert label_from_reasons(["lookalike_domain", "credential_request"]) == Label.PHISHING
    assert label_from_reasons(["dangerous_attachment"]) == Label.PHISHING
    assert label_from_reasons(["suspicious_link", "credential_request"]) == Label.PHISHING
    assert label_from_reasons(["suspicious_link", "payment_request"]) == Label.SUSPICIOUS


# --- false-HOLD rate on the benign samples -----------------------------------

def test_honest_benign_verdicts_never_hold():
    import email
    from email import policy
    from .conftest import SAMPLES
    held = []
    for path in sorted(SAMPLES.glob("benign_*.eml")):
        msg = email.message_from_bytes(path.read_bytes(), policy=policy.default)
        checked = verify("case_test", "sha", msg, _verdict())
        if checked.status == CaseStatus.HOLD:
            held.append((path.name, checked.hold_reason))
    assert held == [], f"verifier false positives: {held}"