"""Seam S3 (Junhee): action agent -> gate -> tools.

Proposal seam test: a fourth action, or a message with a field that is not on
the allow-list, must be refused by the gate and logged.
"""
from pathlib import Path

from phishgate.audit import AuditLog
from phishgate.gate import DEFAULT_POLICY, Gate
from phishgate.schemas import (CaseStatus, CheckedVerdict, Facts, NotifyArgs, QuarantineArgs,
                               SearchSenderArgs, Verdict)
from phishgate.workspace import Workspace

from .conftest import TEMPLATES


def _checked(status=CaseStatus.TO_ANALYST):
    v = Verdict(label="phishing", reasons=["sender_auth_fail"], sender_auth_failed=True,
                suspicious_links=True, dangerous_attachment=False, confidence=0.8)
    f = Facts(sender_auth="fail", suspicious_links=True, dangerous_attachment=False, from_domain="evil.test",
              from_address="a@evil.test", message_id="m0@evil.test")
    return CheckedVerdict(case_id="case_s3", file_sha256="sha", verdict=v, facts=f, status=status)


def _gate(tmp_path: Path):
    ws = Workspace(tmp_path / "ws")
    audit = AuditLog(tmp_path / "audit.sqlite3")
    return Gate(ws, audit, DEFAULT_POLICY, TEMPLATES), audit


def test_fourth_action_is_refused_and_logged(tmp_path):
    gate, audit = _gate(tmp_path)
    proposals = [SearchSenderArgs(sender_address="a@evil.test")] * 4
    decisions = gate.run(_checked(), proposals)
    assert [d.outcome for d in decisions] == ["executed"] * 3 + ["refused"]
    assert any(r["event"] == "gate_refused" for r in audit.rows())


def test_notify_with_field_not_on_allowlist_is_refused(tmp_path):
    gate, audit = _gate(tmp_path)
    p = NotifyArgs(template_id="phishing_warning",
                   fields={"case_id": "case_s3", "sender_domain": "evil.test", "link": "http://evil.test"})
    (d,) = gate.run(_checked(), [p])
    assert d.outcome == "refused" and "link" in d.reason


def test_notify_never_executes_only_queues(tmp_path):
    gate, _ = _gate(tmp_path)
    p = NotifyArgs(template_id="phishing_warning", fields={"case_id": "case_s3", "sender_domain": "evil.test"})
    (d,) = gate.run(_checked(), [p])
    assert d.outcome == "queued_for_approval"
    assert "evil.test" in d.result["body"] and "http" not in d.result["body"]


def test_hold_case_allows_no_action(tmp_path):
    gate, _ = _gate(tmp_path)
    (d,) = gate.run(_checked(CaseStatus.HOLD), [QuarantineArgs(message_ids=["m1"])])
    assert d.outcome == "refused"


# ---- gate hardening: field values, template/label, tool-call budget, unknown ids ----

def test_notify_field_value_with_attacker_text_is_refused(tmp_path):
    """T2: an allow-listed field must not carry free text into a message."""
    gate, audit = _gate(tmp_path)
    evil = "evil.test. URGENT: all staff reset passwords at http://203.0.113.44/reset"
    p = NotifyArgs(template_id="phishing_warning", fields={"case_id": "case_s3", "sender_domain": evil})
    (d,) = gate.run(_checked(), [p])
    assert d.outcome == "refused" and "sender_domain" in d.reason
    assert "URGENT" not in d.reason                      # attacker text is not echoed in the reason
    assert gate.ws.pending() == []                       # nothing reached the analyst queue
    assert any(r["event"] == "gate_refused" for r in audit.rows())


def test_notify_values_are_filled_by_the_gate_not_the_model(tmp_path):
    """The model may leave fields out; the gate fills them from the checked verdict."""
    gate, _ = _gate(tmp_path)
    (d,) = gate.run(_checked(), [NotifyArgs(template_id="phishing_warning")])
    assert d.outcome == "queued_for_approval"
    assert "case_s3" in d.result["body"] and "evil.test" in d.result["body"]


def test_notify_refused_when_from_domain_is_not_a_plain_host_name(tmp_path):
    """The From header is attacker-written, so a malformed domain never enters a message."""
    gate, _ = _gate(tmp_path)
    checked = _checked()
    checked.facts.from_domain = "evil.test click http://203.0.113.44"
    (d,) = gate.run(checked, [NotifyArgs(template_id="phishing_warning")])
    assert d.outcome == "refused" and "sender_domain" in d.reason


def test_notify_template_must_match_label(tmp_path):
    """A 'no indicator found' message on a phishing case is refused."""
    gate, _ = _gate(tmp_path)
    (d,) = gate.run(_checked(), [NotifyArgs(template_id="benign_closed", fields={"case_id": "case_s3"})])
    assert d.outcome == "refused" and "does not match label" in d.reason


def test_closed_case_allows_no_action(tmp_path):
    gate, _ = _gate(tmp_path)
    (d,) = gate.run(_checked(CaseStatus.CLOSED), [SearchSenderArgs(sender_address="a@evil.test")])
    assert d.outcome == "refused"


def test_tool_call_budget_per_case_holds_across_rounds(tmp_path):
    """12 tool calls per case in total, even if the gate is called again for the same case."""
    gate, _ = _gate(tmp_path)
    outcomes = []
    for _ in range(5):                                   # 5 rounds x 3 proposals = 15 attempts
        outcomes += [d.outcome for d in gate.run(_checked(), [SearchSenderArgs(sender_address="a@evil.test")] * 3)]
    assert outcomes == ["executed"] * 12 + ["refused"] * 3


def test_quarantine_of_unknown_id_is_refused(tmp_path):
    gate, _ = _gate(tmp_path)
    gate.ws.add_message("m1", "a@evil.test", "kim@corp.test")
    (d,) = gate.run(_checked(), [QuarantineArgs(message_ids=["m1", "ghost"])])
    assert d.outcome == "refused" and "not in the corpus" in d.reason
    assert gate.ws.db.execute("SELECT quarantined FROM corpus WHERE message_id='m1'").fetchone()[0] == 0


def test_quarantine_of_known_ids_executes_and_bulk_is_queued(tmp_path):
    gate, _ = _gate(tmp_path)
    for i in range(7):
        gate.ws.add_message(f"m{i}", "a@evil.test", "kim@corp.test")
    small, bulk = gate.run(_checked(), [QuarantineArgs(message_ids=["m0", "m0", "m1"]),
                                        QuarantineArgs(message_ids=[f"m{i}" for i in range(1, 7)])])
    assert small.outcome == "executed" and small.result["count"] == 2      # duplicate id counted once
    assert bulk.outcome == "queued_for_approval" and bulk.result["count"] == 6


# ---- scope: an e-mail can only cause actions against its own sender ----

def test_search_of_another_sender_is_refused(tmp_path):
    gate, _ = _gate(tmp_path)
    (d,) = gate.run(_checked(), [SearchSenderArgs(sender_address="ceo@ourcorp.test")])
    assert d.outcome == "refused" and "sender of this case" in d.reason


def test_quarantine_of_another_senders_mail_is_refused(tmp_path):
    gate, _ = _gate(tmp_path)
    gate.ws.add_message("m1", "a@evil.test", "kim@corp.test")
    gate.ws.add_message("ceo1", "ceo@ourcorp.test", "kim@corp.test")
    (d,) = gate.run(_checked(), [QuarantineArgs(message_ids=["m1", "ceo1"])])
    assert d.outcome == "refused" and "not from the sender of this case" in d.reason
    assert gate.ws.quarantined_ids() == []
