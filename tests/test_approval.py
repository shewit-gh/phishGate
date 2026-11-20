"""Layer 5 (S1, plan item S-7): the human approval rules and the approver-fatigue test.

Nothing leaves the system without the analyst's click: every message waits in the
queue, a big quarantine waits, a reject leaves nothing behind, the hourly message
limit holds. The queue can be seeded with bad drafts to measure how many an analyst
approves (proposal section 4, residual risk of layer 5), and the same planted drafts
are all caught by the automatic template check.
"""
import importlib.util
from pathlib import Path

from phishgate.audit import AuditLog
from phishgate.gate import DEFAULT_POLICY, Gate
from phishgate.schemas import CaseStatus, CheckedVerdict, Facts, NotifyArgs, QuarantineArgs, Verdict
from phishgate.workspace import Workspace

from .conftest import TEMPLATES

ROOT = Path(__file__).resolve().parent.parent


def _script():
    spec = importlib.util.spec_from_file_location("approver_fatigue", ROOT / "scripts" / "approver_fatigue.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _checked():
    v = Verdict(label="phishing", reasons=["sender_auth_fail"], sender_auth_failed=True,
                suspicious_links=True, dangerous_attachment=False, confidence=0.8)
    f = Facts(sender_auth="fail", suspicious_links=True, dangerous_attachment=False, from_domain="evil.test",
              from_address="a@evil.test", message_id="m0@evil.test")
    return CheckedVerdict(case_id="case_0a1b2c3d", file_sha256="sha", verdict=v, facts=f,
                          status=CaseStatus.TO_ANALYST)


def _gate(tmp_path: Path):
    ws = Workspace(tmp_path / "ws")
    return Gate(ws, AuditLog(tmp_path / "audit.sqlite3"), DEFAULT_POLICY, TEMPLATES), ws


def _notify():
    return NotifyArgs(template_id="phishing_warning", fields={})


def test_every_message_waits_for_a_click_and_a_reject_leaves_nothing(tmp_path):
    gate, ws = _gate(tmp_path)
    (d,) = gate.run(_checked(), [_notify()])
    assert d.outcome == "queued_for_approval" and not ws.outbox.exists()
    (item,) = ws.pending()
    assert ws.decide(item["item_id"], approve=False)["status"] == "rejected"
    assert not ws.outbox.exists() and ws.pending() == []

    (d,) = gate.run(_checked(), [_notify()])
    (item,) = ws.pending()
    out = ws.decide(item["item_id"], approve=True)
    assert Path(out["outbox_file"]).read_text(encoding="utf-8").startswith("Subject: [Security]")
    assert ws.decide(item["item_id"], approve=True) is None       # one click decides once


def test_bulk_quarantine_waits_and_a_small_one_runs(tmp_path):
    gate, ws = _gate(tmp_path)
    n = DEFAULT_POLICY.bulk_quarantine_threshold
    ids = [f"m{i}@evil.test" for i in range(n + 1)]
    for m in ids:
        ws.add_message(m, "a@evil.test", "minji.park@ourcorp.test")
    (d,) = gate.run(_checked(), [QuarantineArgs(message_ids=ids)])
    assert d.outcome == "queued_for_approval" and ws.quarantined_ids() == []
    (item,) = ws.pending()
    assert item["kind"] == "bulk_quarantine"
    assert sorted(ws.decide(item["item_id"], approve=True)["quarantined"]) == sorted(ids)   # only after the click

    gate2, ws2 = _gate(tmp_path / "second")
    for m in ids[:n]:
        ws2.add_message(m, "a@evil.test", "minji.park@ourcorp.test")
    (d,) = gate2.run(_checked(), [QuarantineArgs(message_ids=ids[:n])])
    assert d.outcome == "executed" and len(ws2.quarantined_ids()) == n


def test_hourly_message_limit_holds(tmp_path):
    gate, ws = _gate(tmp_path)
    for i in range(DEFAULT_POLICY.max_notify_per_hour):
        ws.queue_message(f"case_{i:08x}", "hold_notice", "s", "b")
    (d,) = gate.run(_checked(), [_notify()])
    assert d.outcome == "refused" and "max_notify_per_hour" in d.reason


def test_planted_drafts_are_scored_and_every_bad_one_fails_the_template_check(tmp_path):
    af = _script()
    gate, ws = _gate(tmp_path)
    key = af.plant(ws, good=4, bad=5, seed=1)
    pending = ws.pending()
    assert len(pending) == 9 and set(key) == {p["item_id"] for p in pending}
    assert {v["kind"] for v in key.values() if v["planted"] == "bad"} == set(af.BAD_KINDS)
    for p in pending:
        problems = af.draft_problems(p["payload"])
        assert bool(problems) == (key[p["item_id"]]["planted"] == "bad"), (p["payload"], problems)

    (d,) = gate.run(_checked(), [_notify()])                     # a draft the real gate made passes the same check
    assert af.draft_problems(d.result) == []

    for p in pending:                                           # an analyst who approves everything
        ws.decide(p["item_id"], approve=True)
    s = af.score(ws, key)
    assert s["bad"]["approved"] == 5 and s["good"]["approved"] == 4
    assert s["bad_approved_rate"] == 1.0 and s["good_rejected_rate"] == 0.0 and s["missing_from_queue"] == []

    gate2, ws2 = _gate(tmp_path / "careful")                    # an analyst who rejects every bad draft
    key2 = af.plant(ws2, good=4, bad=5, seed=2)
    for p in ws2.pending():
        ws2.decide(p["item_id"], approve=key2[p["item_id"]]["planted"] == "good")
    s2 = af.score(ws2, key2)
    assert s2["bad_approved_rate"] == 0.0 and s2["good_rejected_rate"] == 0.0 and s2["pending"] == 0
