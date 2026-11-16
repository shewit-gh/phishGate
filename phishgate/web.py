"""Step 7: the analyst page from Figure 1. Local only.

    python -m phishgate.cli serve            # http://127.0.0.1:5000

One page: upload a reported .eml, see the analyst queue (message drafts, bulk
quarantines, HOLD cases), approve or reject, release a quarantine, read the
audit log and the monitor's alerts. It does what the CLI does and nothing more:
an approved message is written to outbox/, nothing is ever sent.

Everything shown here may contain attacker-written text (domains, ids, reasons
quoted from proposals), so:
  * every value goes through Jinja autoescaping; no `|safe`, no JavaScript at all
  * a Content-Security-Policy forbids scripts, frames and remote resources
  * every state change is a POST carrying a per-process secret token (CSRF)
  * the server binds to 127.0.0.1 and has no login: do not expose it
"""
from __future__ import annotations

import hmac
import secrets
import time
from pathlib import Path

from flask import Flask, abort, redirect, render_template_string, request, url_for

from .audit import AbuseMonitor, AuditLog
from .audit.monitor import load_markers
from .intake.intake import MAX_EML_BYTES
from .pipeline import PhishGate
from .tools import quarantine
from .workspace import Workspace

ROOT = Path(__file__).resolve().parent.parent
TEMPLATES = ROOT / "data" / "templates"
MARKERS = ROOT / "data" / "corpus" / "markers.txt"

PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>PhishGate analyst</title>
<style>
 body{font:15px/1.5 system-ui,sans-serif;margin:0;background:#f4f5f7;color:#1c2330}
 header{background:#1c2330;color:#fff;padding:14px 24px} header b{font-size:18px}
 header span{opacity:.7;margin-left:12px} main{max-width:1080px;margin:0 auto;padding:16px 24px 48px}
 h2{font-size:16px;margin:28px 0 8px} .card{background:#fff;border:1px solid #d9dde3;border-radius:8px;padding:12px 16px;margin:8px 0}
 .tag{display:inline-block;font-size:12px;font-weight:600;padding:1px 8px;border-radius:10px;background:#e4e8ee;margin-right:6px}
 .hold{background:#fde8c8} .message{background:#d7e8ff} .bulk{background:#f6d5d5} .ok{background:#d6f0dc} .bad{background:#f6d5d5}
 pre{white-space:pre-wrap;word-break:break-word;background:#f4f5f7;border-radius:6px;padding:8px 10px;margin:8px 0;font-size:13px}
 form{display:inline} button{font:inherit;padding:4px 14px;border-radius:6px;border:1px solid #9aa3b0;background:#fff;cursor:pointer;margin-right:6px}
 button.go{background:#1c2330;color:#fff;border-color:#1c2330}
 table{border-collapse:collapse;width:100%;background:#fff;font-size:13px} td,th{border:1px solid #d9dde3;padding:4px 8px;text-align:left;vertical-align:top}
 td.p{word-break:break-all;font-family:ui-monospace,monospace;font-size:12px} .muted{color:#667085} .flash{background:#fff7d6;border-color:#e6cf7a}
</style></head><body>
<header><b>PhishGate</b><span>analyst page &middot; local workspace &middot; nothing is ever sent</span></header><main>
{% if flash %}<div class="card flash">{{ flash }}</div>{% endif %}

<h2>Report an e-mail</h2>
<div class="card"><form method="post" action="{{ url_for('upload') }}" enctype="multipart/form-data">
 <input type="hidden" name="token" value="{{ token }}"><input type="file" name="eml" accept=".eml" required>
 <button class="go">Triage</button> <span class="muted">model: {{ llm_name }}</span></form></div>

<h2>Analyst queue ({{ pending|length }})</h2>
{% for it in pending %}<div class="card">
 {% if it.kind == 'hold_review' %}<span class="tag hold">HOLD</span>
 {% elif it.kind == 'message' %}<span class="tag message">message draft</span>
 {% else %}<span class="tag bulk">bulk quarantine</span>{% endif %}
 <b>{{ it.case_id }}</b> <span class="muted">{{ it.item_id }} &middot; {{ it.age }}</span>
 {% if it.kind == 'hold_review' %}<pre>{{ it.payload.hold_reason }}</pre>
 {% elif it.kind == 'message' %}<pre>Subject: {{ it.payload.subject }}

{{ it.payload.body }}</pre>
 {% else %}<pre>{{ it.payload.message_ids|length }} messages:
{{ it.payload.message_ids|join('\n') }}</pre>{% endif %}
 {% for act, label in (('approve', 'Reviewed' if it.kind == 'hold_review' else 'Approve'), ('reject', 'Dismiss' if it.kind == 'hold_review' else 'Reject')) %}
 <form method="post" action="{{ url_for('decide', item_id=it.item_id) }}"><input type="hidden" name="token" value="{{ token }}">
  <input type="hidden" name="action" value="{{ act }}"><button class="{{ 'go' if act == 'approve' else '' }}">{{ label }}</button></form>
 {% endfor %}</div>
{% else %}<div class="card muted">Nothing is waiting.</div>{% endfor %}

<h2>Quarantined ({{ quarantined|length }})</h2>
{% for mid in quarantined %}<div class="card"><code>{{ mid }}</code>
 <form method="post" action="{{ url_for('release') }}"><input type="hidden" name="token" value="{{ token }}">
  <input type="hidden" name="message_id" value="{{ mid }}"><button>Release</button></form></div>
{% else %}<div class="card muted">No message is quarantined.</div>{% endfor %}

<h2>Monitor</h2>
<div class="card"><span class="tag {{ 'ok' if chain_ok else 'bad' }}">audit chain {{ 'OK' if chain_ok else 'BROKEN at row ' ~ chain_bad }}</span>
 <span class="tag">{{ summary.cases }} cases</span><span class="tag">HOLD rate {{ '%.0f'|format(summary.hold_rate * 100) }}%</span>
 <span class="tag">{{ summary.gate_refusals }} gate refusals</span><span class="tag">{{ summary.canary_hits }} canary hits</span>
 {% for a in summary.alerts %}<pre>ALERT {{ a }}</pre>{% else %}<p class="muted">No alert.</p>{% endfor %}</div>

<h2>Audit log (last {{ rows|length }} rows)</h2>
<table><tr><th>#</th><th>event</th><th>case</th><th>payload</th></tr>
{% for r in rows %}<tr><td>{{ r.seq }}</td><td>{{ r.event }}</td><td>{{ r.case_id or '-' }}</td><td class="p">{{ r.payload[:400] }}</td></tr>{% endfor %}
</table></main></body></html>"""


def _age(created: float) -> str:
    s = int(time.time() - created)
    return f"{s}s ago" if s < 90 else f"{s // 60} min ago" if s < 5400 else f"{s // 3600} h ago"


def create_app(workspace_dir: Path, llm=None, llm_name: str = "stub") -> Flask:
    from .agents import StubLLM

    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = MAX_EML_BYTES + 64 * 1024     # the upload cap, plus form overhead
    ws_dir = Path(workspace_dir)
    token = secrets.token_urlsafe(32)                                # per process; every POST must carry it

    def stores():
        # sqlite connections belong to one thread, so each request opens its own.
        return Workspace(ws_dir), AuditLog(ws_dir / "audit.sqlite3")

    def check_token():
        if not hmac.compare_digest(request.form.get("token", ""), token):
            abort(400, "missing or wrong form token")

    @app.after_request
    def harden(resp):
        resp.headers["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.get("/")
    def index():
        ws, audit = stores()
        pending = [{**it, "age": _age(it["created"])} for it in ws.pending()]
        chain_ok, chain_bad = audit.verify_chain()
        summary = AbuseMonitor(audit, markers=load_markers(MARKERS)).summary()
        return render_template_string(
            PAGE, pending=pending, quarantined=ws.quarantined_ids(), rows=audit.rows()[-40:][::-1], token=token,
            chain_ok=chain_ok, chain_bad=chain_bad, summary=summary, llm_name=llm_name, flash=request.args.get("m", ""))

    @app.post("/upload")
    def upload():
        check_token()
        f = request.files.get("eml")
        if f is None or not f.filename:
            abort(400, "no file")
        raw = f.read(MAX_EML_BYTES + 1)
        if len(raw) > MAX_EML_BYTES:
            abort(413)
        uploads = ws_dir / "uploads"
        uploads.mkdir(parents=True, exist_ok=True)
        path = uploads / f"{secrets.token_hex(8)}.eml"                # never the client's file name
        path.write_bytes(raw)
        res = PhishGate(ws_dir, llm or StubLLM(), TEMPLATES).run_case(path)
        outcomes = ", ".join(f"{d.proposal.action}: {d.outcome}" for d in res.decisions) or "no action"
        return redirect(url_for("index", m=f"{res.checked.case_id}: {res.checked.status.value} ({outcomes})"))

    @app.post("/decide/<item_id>")
    def decide(item_id: str):
        check_token()
        action = request.form.get("action")
        if action not in ("approve", "reject"):
            abort(400, "unknown action")
        ws, audit = stores()
        out = ws.decide(item_id, approve=action == "approve")
        audit.append(f"analyst_{action}", out["case_id"] if out else None,
                     out or {"item_id": item_id, "error": "not found"})
        return redirect(url_for("index", m=f"{item_id}: {out['status'] if out else 'not found'}"))

    @app.post("/release")
    def release():
        check_token()
        ws, audit = stores()
        out = quarantine.release(ws, "analyst", [request.form.get("message_id", "")])
        audit.append("analyst_release", None, out)
        return redirect(url_for("index", m=f"released {out['count']} message(s)"))

    return app
