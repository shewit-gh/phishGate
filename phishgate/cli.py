"""Command line entry point.

    python -m phishgate.cli run data/samples/benign_invoice.eml --llm stub
    python -m phishgate.cli run data/samples/injected_reset.eml --llm ollama --model qwen2.5:14b
    python -m phishgate.cli queue
    python -m phishgate.cli approve msg_1a2b3c4d
    python -m phishgate.cli audit [--verify]
    python -m phishgate.cli monitor

The Flask analyst page from the diagram is a later step; this CLI is the
analyst for the mid-check slice.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .agents import OllamaClient, StubLLM
from .audit import AbuseMonitor, AuditLog
from .pipeline import PhishGate
from .workspace import Workspace

ROOT = Path(__file__).resolve().parent.parent
TEMPLATES = ROOT / "data" / "templates"


def _llm(args):
    if args.llm == "stub":
        return StubLLM()
    return OllamaClient(model=args.model)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="phishgate")
    ap.add_argument("--workspace", default=str(ROOT / "workspace"))
    sub = ap.add_subparsers(dest="cmd", required=True)

    run = sub.add_parser("run", help="triage one .eml file")
    run.add_argument("eml")
    run.add_argument("--llm", choices=["stub", "ollama"], default="stub")
    run.add_argument("--model", default="qwen2.5:14b")

    sub.add_parser("queue", help="show the analyst queue")
    for name in ("approve", "reject"):
        p = sub.add_parser(name)
        p.add_argument("item_id")
    a = sub.add_parser("audit", help="print the audit log")
    a.add_argument("--verify", action="store_true")
    sub.add_parser("monitor", help="abuse-monitor summary")

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

    ws = Workspace(ws_dir)
    audit = AuditLog(ws_dir / "audit.sqlite3")
    if args.cmd == "queue":
        for item in ws.pending():
            print(json.dumps(item, ensure_ascii=False))
    elif args.cmd in ("approve", "reject"):
        out = ws.decide(args.item_id, approve=args.cmd == "approve")
        audit.append(f"analyst_{args.cmd}", None, out or {"item_id": args.item_id, "error": "not found"})
        print(json.dumps(out))
    elif args.cmd == "audit":
        for r in audit.rows():
            print(f"{r['seq']:>4} {r['event']:<24} {r['case_id'] or '-':<14} {r['payload'][:100]}")
        if args.verify:
            ok, bad = audit.verify_chain()
            print("chain OK" if ok else f"CHAIN BROKEN at seq {bad}")
            return 0 if ok else 1
    elif args.cmd == "monitor":
        print(json.dumps(AbuseMonitor(audit).summary(), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
