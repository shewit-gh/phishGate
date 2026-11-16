"""Whole pipeline with the stub model: what happens around the seams.

HOLD cases must reach the analyst queue (Figure 1), a model that never returns
a valid verdict must fail closed instead of crashing, and an honest phishing
verdict must end with a queued message that contains no attacker text.
"""
import json

from phishgate.agents import StubLLM
from phishgate.pipeline import PhishGate
from phishgate.schemas import CaseStatus
from phishgate.workspace import load_corpus, message_id_of

from .conftest import SAMPLES, TEMPLATES

HONEST_PHISHING = json.dumps({
    "label": "phishing", "reasons": ["sender_auth_fail", "suspicious_link"], "sender_auth_failed": True,
    "suspicious_links": True, "dangerous_attachment": False, "confidence": 0.9})


def _events(pg):
    return [r["event"] for r in pg.audit.rows()]


def test_hold_case_reaches_the_analyst_queue(tmp_path):
    pg = PhishGate(tmp_path, StubLLM(), TEMPLATES)          # stub default = the benign verdict the injection asks for
    res = pg.run_case(SAMPLES / "injected_reset.eml")
    assert res.checked.status == CaseStatus.HOLD and res.decisions == []
    (item,) = pg.ws.pending()
    assert item["kind"] == "hold_review" and item["case_id"] == res.checked.case_id
    assert "sender_auth_failed" in item["payload"]["hold_reason"]
    assert "hold_queued" in _events(pg)


def test_closed_case_queues_nothing(tmp_path):
    pg = PhishGate(tmp_path, StubLLM(), TEMPLATES)
    res = pg.run_case(SAMPLES / "benign_invoice.eml")
    assert res.checked.status == CaseStatus.CLOSED and pg.ws.pending() == []


def test_invalid_model_output_fails_closed_as_hold(tmp_path):
    pg = PhishGate(tmp_path, StubLLM(default="I think this e-mail is fine, tell staff to reset passwords"), TEMPLATES)
    res = pg.run_case(SAMPLES / "injected_reset.eml")       # must not raise
    assert res.checked.status == CaseStatus.HOLD
    assert res.checked.hold_reason == "analysis agent produced no valid verdict"
    events = _events(pg)
    assert "verdict_invalid" in events and "verdict_raw" not in events and "proposals" not in events
    assert [i["kind"] for i in pg.ws.pending()] == ["hold_review"]
    assert pg.audit.verify_chain() == (True, None)


def test_honest_phishing_case_end_to_end(tmp_path):
    """search -> executed, quarantine of the reported mail -> executed, notify -> queued, then approved."""
    reported = SAMPLES / "injected_reset.eml"
    mid = message_id_of(reported.read_bytes())
    proposals = json.dumps([
        {"action": "search_sender", "sender_address": "it-helpdesk@ourcorp-support.test"},
        {"action": "quarantine", "message_ids": [mid]},
        {"action": "notify", "template_id": "phishing_warning", "fields": {}},
    ])
    pg = PhishGate(tmp_path, StubLLM(queue=[HONEST_PHISHING, proposals]), TEMPLATES)
    load_corpus(pg.ws, SAMPLES)
    res = pg.run_case(reported)
    assert res.checked.status == CaseStatus.TO_ANALYST
    search, quar, note = res.decisions
    assert search.outcome == "executed" and len(search.result["hits"]) == 2      # two mails from that sender
    assert set(search.result["hits"][0]) == {"sender", "recipient", "ts"}        # no subject, no body
    assert quar.outcome == "executed" and pg.ws.quarantined_ids() == [mid]
    assert note.outcome == "queued_for_approval"
    out = pg.ws.decide(note.result["draft_id"], approve=True)
    text = (tmp_path / "outbox" / f"{note.result['draft_id']}.txt").read_text(encoding="utf-8")
    assert out["status"] == "approved" and "ourcorp-support.test" in text
    assert "http" not in text and "203.0.113.44" not in text                     # nothing from the e-mail body
