"""Defence layer 6 (Diva): the audit log is tamper-evident."""
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
