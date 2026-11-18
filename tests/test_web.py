"""The analyst page: same actions as the CLI, attacker text is escaped, state changes need the form token."""
import io
import json
import re

import pytest

from phishgate.agents import StubLLM
from phishgate.audit import AuditLog
from phishgate.web import create_app
from phishgate.workspace import Workspace, load_corpus, message_id_of

from .conftest import SAMPLES


@pytest.fixture
def client(tmp_path):
    app = create_app(tmp_path / "ws")
    app.config["TESTING"] = True
    return app.test_client(), tmp_path / "ws"


def _token(c):
    return re.search(r'name="token" value="([^"]+)"', c.get("/").get_data(as_text=True)).group(1)


def _upload(c, name, token):
    data = {"token": token, "eml": (io.BytesIO((SAMPLES / name).read_bytes()), "whatever.eml")}
    return c.post("/upload", data=data, content_type="multipart/form-data", follow_redirects=True)


def test_page_loads_with_security_headers(client):
    c, _ = client
    r = c.get("/")
    assert r.status_code == 200 and "Nothing is waiting." in r.get_data(as_text=True)
    assert "default-src 'none'" in r.headers["Content-Security-Policy"] and r.headers["X-Frame-Options"] == "DENY"


def test_post_without_token_is_refused(client):
    c, ws_dir = client
    Workspace(ws_dir).queue_hold_review("case_x", "reason")
    item = Workspace(ws_dir).pending()[0]["item_id"]
    assert c.post(f"/decide/{item}", data={"action": "approve"}).status_code == 400
    assert c.post(f"/decide/{item}", data={"action": "approve", "token": "guess"}).status_code == 400
    assert c.post("/release", data={"message_id": "m"}).status_code == 400
    assert len(Workspace(ws_dir).pending()) == 1                      # nothing changed


def test_upload_of_injected_mail_shows_a_hold_and_review_is_logged(client):
    c, ws_dir = client
    token = _token(c)
    page = _upload(c, "injected_reset.eml", token).get_data(as_text=True)
    assert "HOLD" in page and "sender_auth_failed claimed False" in page
    item = Workspace(ws_dir).pending()[0]
    c.post(f"/decide/{item['item_id']}", data={"action": "approve", "token": token})
    assert Workspace(ws_dir).pending() == []
    last = AuditLog(ws_dir / "audit.sqlite3").rows()[-1]
    assert last["event"] == "analyst_approve" and last["case_id"] == item["case_id"]


def test_message_draft_is_approved_into_the_outbox(tmp_path):
    verdict = {"label": "phishing", "reasons": ["sender_auth_fail"], "sender_auth_failed": True,
               "suspicious_links": True, "dangerous_attachment": False, "confidence": 0.9}
    proposals = [{"action": "notify", "template_id": "phishing_warning", "fields": {}}]
    app = create_app(tmp_path / "ws", llm=StubLLM(queue=[json.dumps(verdict), json.dumps(proposals)]))
    c = app.test_client()
    token = _token(c)
    assert "message draft" in _upload(c, "injected_reset.eml", token).get_data(as_text=True)
    item = Workspace(tmp_path / "ws").pending()[0]
    c.post(f"/decide/{item['item_id']}", data={"action": "approve", "token": token})
    text = (tmp_path / "ws" / "outbox" / f"{item['item_id']}.txt").read_text(encoding="utf-8")
    assert "ourcorp-support.test" in text and "http" not in text


def test_attacker_text_is_escaped(client):
    c, ws_dir = client
    Workspace(ws_dir).queue_hold_review("case_x", '<script>alert(1)</script><img src=x onerror=alert(2)>')
    AuditLog(ws_dir / "audit.sqlite3").append("gate_refused", "case_x", {"reason": "<b>bold</b>"})
    page = c.get("/").get_data(as_text=True)
    assert "<script>alert(1)" not in page and "&lt;script&gt;alert(1)" in page
    assert "<img src=x" not in page and "<b>bold</b>" not in page


def test_release_from_the_page(client):
    c, ws_dir = client
    ws = Workspace(ws_dir)
    load_corpus(ws, SAMPLES)
    mid = message_id_of((SAMPLES / "phish_punycode_ko.eml").read_bytes())
    ws.set_quarantine([mid], True, "case_x")
    token = _token(c)
    assert mid in c.get("/").get_data(as_text=True)
    c.post("/release", data={"message_id": mid, "token": token})
    assert Workspace(ws_dir).quarantined_ids() == []
