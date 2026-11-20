"""Run the whole pipeline over a labelled corpus and print the numbers from proposal section 5.

    python scripts/make_corpus.py
    python scripts/evaluate.py                                  # stub model, no GPU
    python scripts/evaluate.py --llm ollama --model qwen2.5:14b # the real numbers
    python scripts/evaluate.py --limit 40 --json out.json

With `--llm stub` the "model" answers benign to everything. That is a model
that obeyed every injection, so the result is a floor: what the verifier and
the gate stop on their own when the model is fully compromised. It says
nothing about the model's precision and recall; those need `--llm ollama`.

The corpus folder needs a labels.csv (written by make_corpus.py).
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
import tempfile
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from phishgate.agents import OllamaClient, StubLLM          # noqa: E402
from phishgate.audit import AbuseMonitor                    # noqa: E402
from phishgate.audit.monitor import load_markers            # noqa: E402
from phishgate.pipeline import PhishGate                    # noqa: E402
from phishgate.workspace import load_corpus                 # noqa: E402


def _ratio(a: int, b: int) -> float | None:
    return round(a / b, 4) if b else None


def evaluate(corpus: Path, llm, limit: int | None = None, workspace: Path | None = None) -> dict:
    rows = list(csv.DictReader((corpus / "labels.csv").open(encoding="utf-8")))
    if limit:
        step = max(1, len(rows) // limit)
        rows = rows[::step][:limit]            # spread over benign / phishing / injected
    ws_dir = workspace or Path(tempfile.mkdtemp(prefix="phishgate_eval_"))
    pg = PhishGate(ws_dir, llm, ROOT / "data" / "templates")
    load_corpus(pg.ws, corpus)

    tp = fp = fn = tn = 0
    outcome: dict[str, Counter] = {"benign": Counter(), "phishing": Counter(), "injected": Counter()}
    by_injection: dict[str, Counter] = {}
    by_category: dict[str, Counter] = {}       # taxonomy category of every attack mail (proposal: "per attack type")
    for row in rows:
        res = pg.run_case(corpus / row["file"])
        group = "injected" if row["injection"] else row["label"]
        status = res.checked.status.value
        outcome[group][status] += 1
        if row["injection"]:
            by_injection.setdefault(row["injection"], Counter())[status] += 1
        if row["label"] == "phishing":
            by_category.setdefault(row.get("taxonomy") or row["kind"], Counter())[status] += 1
        said_bad = res.checked.verdict.label.value != "benign"      # the model's own label
        is_bad = row["label"] == "phishing"
        tp, fp, fn, tn = tp + (said_bad and is_bad), fp + (said_bad and not is_bad), \
            fn + (not said_bad and is_bad), tn + (not said_bad and not is_bad)

    audit_rows = pg.audit.rows()
    events = Counter(r["event"] for r in audit_rows)
    cases = {r["case_id"] for r in audit_rows if r["event"] == "intake"}
    traced = {r["case_id"] for r in audit_rows if r["event"] == "verdict_checked"}
    limit_refusals = sum(1 for r in audit_rows if r["event"] == "gate_refused"
                         and json.loads(r["payload"])["reason"].startswith(("exceeds", "max_notify")))
    monitor = AbuseMonitor(pg.audit, markers=load_markers(corpus.parent / "markers.txt"))
    n_ben, n_phi, n_inj = (sum(outcome[k].values()) for k in ("benign", "phishing", "injected"))
    return {
        "cases": len(rows),
        "groups": {k: dict(v) for k, v in outcome.items()},
        "model_precision": _ratio(tp, tp + fp),
        "model_recall": _ratio(tp, tp + fn),
        # System-level numbers: what happened to the case, whatever the model said.
        "evasion_rate_phishing": _ratio(outcome["phishing"]["closed"], n_phi),       # phishing closed as benign
        "evasion_rate_injected": _ratio(outcome["injected"]["closed"], n_inj),       # target <= 0.10 after layer 3
        "hold_rate_on_benign": _ratio(outcome["benign"]["hold"], n_ben),             # target <= 0.05
        "injected_by_technique": {k: dict(v) for k, v in sorted(by_injection.items())},
        "evasion_by_category": {k: {"cases": sum(v.values()), "closed": v["closed"],
                                    "rate": _ratio(v["closed"], sum(v.values()))}
                                for k, v in sorted(by_category.items())},
        "gate_refusals": events.get("gate_refused", 0),
        "refusals_for_limits": limit_refusals,
        "messages_queued": events.get("notify_queued", 0),
        "invalid_verdicts": events.get("verdict_invalid", 0),
        "cases_traced": _ratio(len(traced & cases), len(cases)),                    # target 1.0
        "audit_chain_ok": pg.audit.verify_chain()[0],
        "canary_hits": len(monitor.canary_hits()),                                  # target 0
        "markers_loaded": len(monitor.markers),
        "workspace": str(ws_dir),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--corpus", default=str(ROOT / "data" / "corpus" / "generated"))
    ap.add_argument("--llm", choices=["stub", "ollama"], default="stub")
    ap.add_argument("--model", default="qwen2.5:14b")
    ap.add_argument("--limit", type=int, help="evaluate about this many mails, spread over the corpus")
    ap.add_argument("--json", help="also write the result to this file")
    args = ap.parse_args()
    corpus = Path(args.corpus)
    if not (corpus / "labels.csv").exists():
        print(f"no labels.csv in {corpus}; run scripts/make_corpus.py first", file=sys.stderr)
        return 2
    llm = StubLLM() if args.llm == "stub" else OllamaClient(model=args.model)
    result = {"llm": args.llm if args.llm == "stub" else args.model, **evaluate(corpus, llm, args.limit)}
    text = json.dumps(result, indent=2, ensure_ascii=False)
    print(text)
    if args.json:
        Path(args.json).write_text(text + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
