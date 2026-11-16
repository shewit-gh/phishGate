"""Command line entry point.

    python -m phishgate.cli run data/samples/benign_invoice.eml --llm stub
    python -m phishgate.cli run data/samples/injected_reset.eml --llm ollama --model qwen2.5:14b
    python -m phishgate.cli load-corpus data/samples
    python -m phishgate.cli queue
    python -m phishgate.cli approve msg_1a2b3c4d
    python -m phishgate.cli quarantined
    python -m phishgate.cli release "<message-id>"
    python -m phishgate.cli audit [--verify]
    python -m phishgate.cli serve                 # the analyst page on http://127.0.0.1:5000
    python -m phishgate.cli monitor

The Flask analyst page from the diagram is a later step; this CLI is the
analyst for the mid-check slice.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .agents import OllamaClient, StubLLM
from .audit.monitor import load_markers
from .audit import AbuseMonitor, AuditLog
from .pipeline import PhishGate
from .tools import quarantine
from .workspace import Workspace, load_corpus

ROOT = Path(__file__).resolve().parent.parent
TEMPLATES = ROOT / "data" / "templates"
MARKERS = ROOT / "data" / "corpus" / "markers.txt"


def _llm(args):
    if args.llm == "stub":
        # --stub-file: a JSON list of canned model outputs, used in order (analysis first, then action).
        # Lets the whole path be shown without a GPU. Not a model: it says what the file tells it to.
        queue = json.loads(Path(args.stub_file).read_text(encoding="utf-8")) if args.stub_file else []
        return StubLLM(queue=[q if isinstance(q, str) else json.dumps(q) for q in queue])
    return OllamaClient(model=args.model)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="phishgate")
    ap.add_argument("--workspace", default=str(ROOT / "workspace"))
    sub = ap.add_subparsers(dest="cmd", required=True)

    run = sub.add_parser("run", help="triage one .eml file")
    run.add_argument("eml")
    run.add_argument("--llm", choices=["stub", "ollama"], default="stub")
    run.add_argument("--model", default="qwen2.5:14b")
    run.add_argument("--stub-file", help="JSON list of canned model outputs for --llm stub")

    lc = sub.add_parser("load-corpus", help="index a folder of .eml files into the workspace")
    lc.add_argument("folder")
    sub.add_parser("quarantined", help="list quarantined message ids")
    rel = sub.add_parser("release", help="analyst: undo a quarantine")
    rel.add_argument("message_ids", nargs="+")
    sub.add_parser("queue", help="show the analyst queue")
    for name in ("approve", "reject"):
        p = sub.add_parser(name)
        p.add_argument("item_id")
    a = sub.add_parser("audit", help="print the audit log")
    a.add_argument("--verify", action="store_true")
    sub.add_parser("monitor", help="abuse-monitor summary")
    srv = sub.add_parser("serve", help="analyst web page (binds to 127.0.0.1 only)")
    srv.add_argument("--port", type=int, default=5000)
    srv.add_argument("--llm", choices=["stub", "ollama"], default="stub")
    srv.add_argument("--model", default="qwen2.5:14b")
    srv.add_argument("--stub-file", help="JSON list of canned model outputs for --llm stub")

    args = ap.parse_args(argv)
    ws_dir = Path(args.workspace)

    if args.cmd == "run":
        pg = PhishGate(ws_dir, _llm(args), TEMPLATES)
        res = pg.run_case(Path(args.eml))
        print(json.dumps({
            "case_id": res.checked.case_id,
            "status": res.checked.status.value,
            "label": res.checked.verdict.label.value,
            "hold_reason": res.checked.hold_reason,
            "facts": res.checked.facts.model_dump(),
            "gate": [{"action": d.proposal.action, "outcome": d.outcome, "reason": d.reason} for d in res.decisions],
        }, indent=2, ensure_ascii=False))
        return 0

    if args.cmd == "serve":
        from .web import create_app          # imported here so the CLI works without Flask installed
        app = create_app(ws_dir, _llm(args), args.llm if args.llm == "stub" else args.model)
        app.run(host="127.0.0.1", port=args.port, debug=False)
        return 0

    ws = Workspace(ws_dir)
    audit = AuditLog(ws_dir / "audit.sqlite3")
    if args.cmd == "load-corpus":
        out = load_corpus(ws, Path(args.folder))
        audit.append("corpus_loaded", None, {"folder": args.folder, **out})
        print(json.dumps(out, ensure_ascii=False))
    elif args.cmd == "quarantined":
        for mid in ws.quarantined_ids():
            print(mid)
    elif args.cmd == "release":
        out = quarantine.release(ws, "analyst", args.message_ids)
        audit.append("analyst_release", None, out)
        print(json.dumps(out, ensure_ascii=False))
    elif args.cmd == "queue":
        for item in ws.pending():
            print(json.dumps(item, ensure_ascii=False))
    elif args.cmd in ("approve", "reject"):
        out = ws.decide(args.item_id, approve=args.cmd == "approve")
        audit.append(f"analyst_{args.cmd}", out["case_id"] if out else None,
                     out or {"item_id": args.item_id, "error": "not found"})
        print(json.dumps(out))
    elif args.cmd == "audit":
        for r in audit.rows():
            print(f"{r['seq']:>4} {r['event']:<24} {r['case_id'] or '-':<14} {r['payload'][:100]}")
        if args.verify:
            ok, bad = audit.verify_chain()
            print("chain OK" if ok else f"CHAIN BROKEN at seq {bad}")
            return 0 if ok else 1
    elif args.cmd == "monitor":
        print(json.dumps(AbuseMonitor(audit, markers=load_markers(MARKERS)).summary(), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
