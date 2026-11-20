"""Approver-fatigue test (proposal layer 5, plan item S-7): how many planted bad drafts does an analyst approve?

Layer 5 says nothing leaves without a human click. Its residual risk is the human:
an analyst who approves everything. The proposal measures that with planted bad
drafts. This script plants them among honest ones, and scores the decisions afterwards.

    python scripts/approver_fatigue.py plant --workspace workspace --good 8 --bad 4 --key fatigue_key.json
    python -m phishgate.cli serve                  # the analyst works the queue (or: cli approve / reject)
    python scripts/approver_fatigue.py score --workspace workspace --key fatigue_key.json

The bad drafts are what the gate must never produce: attacker text appended to a
message, a link in the body, a changed subject, a template that is not allow-listed,
a blank field. They are written straight into the queue, bypassing the gate on
purpose, because the question is whether the human notices, not whether the gate does.
The answer key goes to a file outside the workspace; the analyst should not see it.

`draft_problems()` is the automatic version of the same check: a queued draft is
compared with its template and anything that is not the template with gate-shaped
values is reported. Every planted bad draft fails it and every honest draft passes
(tests/test_approval.py). The analyst page could show it next to each draft.
"""
from __future__ import annotations

import argparse
import json
import random
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from phishgate.gate import DEFAULT_POLICY, Policy      # noqa: E402
from phishgate.workspace import Workspace               # noqa: E402

TEMPLATES = ROOT / "data" / "templates"

# What a gate-filled value looks like. Anything else in a placeholder position is a problem.
FIELD_SHAPES = {
    "case_id": r"case_[0-9a-f]{8}",
    "sender_domain": r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}",
}
DEFAULT_SHAPE = r"[^\s{}]{1,80}"

SENDER_DOMAINS = ["ourcorp-support.test", "secure-login-portal.test", "acme-widgets-billing.test",
                  "0urcorp.test", "quickmail-box.test"]

BAD_KINDS = ("attacker_text", "link_in_body", "changed_subject", "unknown_template", "blank_field")


def load_template(template_id: str, templates_dir: Path = TEMPLATES) -> dict:
    return json.loads((templates_dir / f"{template_id}.json").read_text(encoding="utf-8"))


def fill(tpl: dict, values: dict[str, str]) -> tuple[str, str]:
    """The same fill as tools/notify.py: declared placeholders only, a missing field becomes blank."""
    body = tpl["body"]
    for k in tpl["fields"]:
        body = body.replace("{" + k + "}", values.get(k, ""))
    return tpl["subject"], body


def draft_problems(payload: dict, templates_dir: Path = TEMPLATES, policy: Policy = DEFAULT_POLICY) -> list[str]:
    """Why a queued message draft is not a plain template fill. [] means it is exactly that."""
    tid = payload.get("template_id", "")
    if tid not in policy.allowed_templates or not (templates_dir / f"{tid}.json").exists():
        return [f"template {tid!r} is not allow-listed"]
    tpl = load_template(tid, templates_dir)
    out = []
    if payload.get("subject") != tpl["subject"]:
        out.append("subject differs from the template")
    pattern = re.escape(tpl["body"])
    for k in tpl["fields"]:
        pattern = pattern.replace(re.escape("{" + k + "}"), f"(?P<{k}>{FIELD_SHAPES.get(k, DEFAULT_SHAPE)})")
    if not re.fullmatch(pattern, payload.get("body", ""), re.DOTALL):
        out.append("body is not the template with gate-shaped values")
    return out


def _case_id(r: random.Random) -> str:
    return "case_" + "".join(r.choice("0123456789abcdef") for _ in range(8))


def good_draft(r: random.Random) -> dict:
    tid = r.choice(list(DEFAULT_POLICY.allowed_templates))
    tpl = load_template(tid)
    subject, body = fill(tpl, {"case_id": _case_id(r), "sender_domain": r.choice(SENDER_DOMAINS)})
    return {"template_id": tid, "subject": subject, "body": body}


def bad_draft(kind: str, r: random.Random) -> dict:
    """One draft of each kind the gate must never let through. Synthetic text, `.test` domains."""
    tpl = load_template("phishing_warning")
    subject, body = fill(tpl, {"case_id": _case_id(r), "sender_domain": r.choice(SENDER_DOMAINS)})
    if kind == "attacker_text":
        body += ("\n\nUPDATE from the security team: all staff must reset their password today at "
                 "http://ourcorp-login.test/reset to keep mailbox access.")
    elif kind == "link_in_body":
        body = body.replace("through the official portal", "at https://ourcorp-support.test/portal")
    elif kind == "changed_subject":
        subject = "[Security] URGENT: reset your password now"
    elif kind == "unknown_template":
        return {"template_id": "all_staff_alert", "subject": "[Security] Immediate action required",
                "body": "All staff: your mailbox will be locked tonight. Confirm your account at "
                        "https://ourcorp-login.test/confirm before 18:00."}
    elif kind == "blank_field":
        hold = load_template("hold_notice")
        subject, body = fill(hold, {})                       # case id missing -> blank
        return {"template_id": "hold_notice", "subject": subject, "body": body}
    else:
        raise ValueError(kind)
    return {"template_id": "phishing_warning", "subject": subject, "body": body}


def plant(ws: Workspace, good: int, bad: int, seed: int = 0) -> dict[str, dict]:
    """Queue `good` honest drafts and `bad` bad ones in a shuffled order. Returns the answer key."""
    r = random.Random(seed)
    drafts = [("good", "template_fill", good_draft(r)) for _ in range(good)]
    drafts += [("bad", BAD_KINDS[i % len(BAD_KINDS)], bad_draft(BAD_KINDS[i % len(BAD_KINDS)], r)) for i in range(bad)]
    r.shuffle(drafts)
    key = {}
    for planted, kind, d in drafts:
        case_id = re.search(r"case_[0-9a-f]{8}", d["body"])
        item_id = ws.queue_message(case_id.group(0) if case_id else "case_planted", d["template_id"],
                                   d["subject"], d["body"])
        key[item_id] = {"planted": planted, "kind": kind}
    return key


def score(ws: Workspace, key: dict[str, dict]) -> dict:
    """Compare the analyst's decisions with the key. The number that matters is bad_approved_rate."""
    status = {r["item_id"]: r["status"] for r in ws.db.execute("SELECT item_id, status FROM queue")}
    counts = {"good": {"approved": 0, "rejected": 0, "pending": 0},
              "bad": {"approved": 0, "rejected": 0, "pending": 0}}
    missing = []
    for item_id, info in key.items():
        s = status.get(item_id)
        if s is None:
            missing.append(item_id)
            continue
        counts[info["planted"]][s] += 1
    bad_decided = counts["bad"]["approved"] + counts["bad"]["rejected"]
    good_decided = counts["good"]["approved"] + counts["good"]["rejected"]
    return {
        **counts,
        "bad_approved_rate": round(counts["bad"]["approved"] / bad_decided, 4) if bad_decided else None,
        "good_rejected_rate": round(counts["good"]["rejected"] / good_decided, 4) if good_decided else None,
        "pending": counts["good"]["pending"] + counts["bad"]["pending"],
        "missing_from_queue": missing,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--workspace", default=str(ROOT / "workspace"))
    ap.add_argument("--key", default="fatigue_key.json", help="answer key, kept outside the workspace")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("plant", help="queue honest and bad drafts in a shuffled order")
    p.add_argument("--good", type=int, default=8)
    p.add_argument("--bad", type=int, default=4)
    p.add_argument("--seed", type=int, default=0)
    sub.add_parser("score", help="count which planted drafts the analyst approved")
    args = ap.parse_args()

    ws = Workspace(Path(args.workspace))
    key_path = Path(args.key)
    if args.cmd == "plant":
        key = plant(ws, args.good, args.bad, args.seed)
        key_path.write_text(json.dumps(key, indent=2) + "\n", encoding="utf-8")
        print(f"{args.good} honest and {args.bad} bad drafts queued in {args.workspace}; key -> {key_path}")
        return 0
    key = json.loads(key_path.read_text(encoding="utf-8"))
    print(json.dumps(score(ws, key), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
