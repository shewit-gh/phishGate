"""Defence layer 6: the audit log is tamper-evident."""

import pytest
from phishgate.audit import AuditLog

def test_chain_verifies_and_breaks_on_edit(tmp_path):
    log = AuditLog(tmp_path / "a.sqlite3")
    log.append("intake", "c1", {"sha256": "x"})
    log.append("verdict_raw", "c1", {"label": "phishing"})
    assert log.verify_chain() == (True, None)
    log.db.execute("UPDATE audit SET payload = ? WHERE seq = 2", ('{"label":"benign"}',))
    log.db.commit()
    ok, bad = log.verify_chain()
    assert not ok and bad == 2

def test_every_action_traces_to_a_checked_verdict(tmp_path):
    log = AuditLog(tmp_path / "a.sqlite3")
    log.append("verdict_checked", "c1", {"status": "to_analyst"})
    log.append("notify_queued", "c1", {})
    log.append("quarantine_executed", "c2", {})      # c2 never had a verdict
    assert log.untraced_actions() == [3]


def test_model_calls_are_logged_and_capped(tmp_path):
    from phishgate.agents import AuditedLLM, ModelBudgetExceeded, StubLLM
    log = AuditLog(tmp_path / "a.sqlite3")
    llm = AuditedLLM(StubLLM(), log, max_calls_per_case=2)
    llm.start_case("c1")
    llm.complete("sys", "SECRET MAIL BODY")
    llm.complete("sys", "SECRET MAIL BODY")
    with pytest.raises(ModelBudgetExceeded):
        llm.complete("sys", "SECRET MAIL BODY")
    events = [r["event"] for r in log.rows()]
    assert events == ["model_call", "model_call", "budget_exceeded"]
    assert "SECRET MAIL BODY" not in log.rows()[0]["payload"]   # hashes only


def test_pipeline_logs_each_model_call(tmp_path):
    from phishgate.agents import StubLLM
    from phishgate.pipeline import PhishGate
    from .conftest import SAMPLES, TEMPLATES
    pg = PhishGate(tmp_path, StubLLM(), TEMPLATES)
    pg.run_case(SAMPLES / "benign_invoice.eml")
    events = [r["event"] for r in pg.audit.rows()]
    assert events.index("model_call") < events.index("verdict_raw")
    assert pg.audit.untraced_actions() == []
    assert pg.audit.verify_chain() == (True, None)
