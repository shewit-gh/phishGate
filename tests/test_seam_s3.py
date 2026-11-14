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
    f = Facts(sender_auth="fail", suspicious_links=True, dangerous_attachment=False, from_domain="evil.test")
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
