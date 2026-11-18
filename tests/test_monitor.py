"""Defence layer 6: the abuse monitor raises alerts from the audit log alone."""
from phishgate.audit import AbuseMonitor, AuditLog
from phishgate.audit.monitor import Thresholds


def _log(tmp_path):
    return AuditLog(tmp_path / "a.sqlite3")


def _alerts(log, **kw):
    return {a["alert"]: a for a in AbuseMonitor(log, **kw).alerts()}


def test_quiet_log_raises_nothing(tmp_path):
    log = _log(tmp_path)
    log.append("verdict_checked", "c1", {"status": "closed", "label": "benign", "from_domain": "x.test"})
    assert AbuseMonitor(log).alerts() == []


def test_hold_rate_alert_needs_enough_cases(tmp_path):
    log = _log(tmp_path)
    for i in range(4):
        log.append("verdict_checked", f"c{i}", {"status": "hold", "label": "benign", "from_domain": f"d{i}.test"})
    assert "hold_rate" not in _alerts(log)                       # 4 cases: too few to call it a rate
    for i in range(4, 10):
        log.append("verdict_checked", f"c{i}", {"status": "closed", "label": "benign", "from_domain": f"d{i}.test"})
    assert _alerts(log)["hold_rate"]["value"] == 0.4


def test_refusals_and_limit_overruns(tmp_path):
    log = _log(tmp_path)
    for _ in range(4):
        log.append("gate_refused", "c1", {"reason": "exceeds max_actions_per_case=3"})
    a = _alerts(log)
    assert a["refusals_per_case"]["case_id"] == "c1" and a["limit_overruns"]["value"] == 4


def test_message_volume(tmp_path):
    log = _log(tmp_path)
    for i in range(9):
        log.append("notify_queued", f"c{i}", {"draft_id": f"msg_{i}"})
    assert _alerts(log)["message_volume"]["value"] == 9


def test_domain_closed_as_benign_after_it_was_flagged(tmp_path):
    log = _log(tmp_path)
    log.append("verdict_checked", "c1", {"status": "hold", "label": "benign", "from_domain": "ourcorp-support.test"})
    log.append("verdict_checked", "c2", {"status": "closed", "label": "benign", "from_domain": "ourcorp-support.test"})
    assert _alerts(log)["safe_after_flagged"]["from_domain"] == "ourcorp-support.test"


def test_canary_marker_in_an_outgoing_row_is_a_hit(tmp_path):
    log = _log(tmp_path)
    marker = "CANARY-7f3a91c2"
    log.append("intake", "c1", {"note": marker})                              # raw input is not scanned
    log.append("notify_queued", "c1", {"body": f"Case c1 ... {marker}"})
    hit = _alerts(log, markers=[marker])["canary_hit"]
    assert hit["event"] == "notify_queued" and hit["marker"] == 0
    assert marker not in str(hit)                                             # the secret is not repeated
    assert AbuseMonitor(log, Thresholds(), [marker]).summary()["canary_hits"] == 1


def test_model_budget_alerts(tmp_path):
    log = _log(tmp_path)
    for i in range(5):
        log.append("model_call", "c1", {"n": i + 1})
    log.append("budget_exceeded", "c2", {"what": "model_calls", "limit": 6})
    a = _alerts(log)
    assert a["model_calls_per_case"]["case_id"] == "c1" and a["model_calls_per_case"]["value"] == 5
    assert a["budget_exceeded"]["case_id"] == "c2"
    s = AbuseMonitor(log).summary()
    assert s["model_calls"] == 5 and s["budget_overruns"] == 1


def test_untraced_action_is_an_alert(tmp_path):
    log = _log(tmp_path)
    log.append("verdict_checked", "c1", {"status": "to_analyst", "label": "phishing", "from_domain": "x.test"})
    log.append("notify_queued", "c1", {"draft_id": "m1"})
    log.append("quarantine_executed", "c9", {"message_ids": ["z"]})     # c9 never had a verdict
    a = _alerts(log)
    assert a["untraced_action"]["seq"] == 3
    assert AbuseMonitor(log).summary()["untraced_actions"] == 1