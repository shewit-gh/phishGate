"""ABUSE MONITOR: reads the audit log after the fact (defence layer 6).

Watches (proposal section 4, layer 6): HOLD rate, limit overruns, refusals per
case, message volume, a sender domain that is judged safe after it was flagged,
and canary-marker hits. Detection, not prevention: the gate and the verifier
stop things, the monitor tells a human that someone is trying.

Canary markers are secret strings planted in corpus mail bodies
(data/corpus/markers.txt, written by scripts/make_corpus.py). No row written
after intake should ever contain one: the analysis agent may output closed
vocabularies only, and the control zone never sees e-mail text. A hit means
e-mail content crossed trust boundary 1.
"""
from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from .audit_log import AuditLog

# Rows that legitimately hold raw input and are therefore not scanned for markers.
_NOT_SCANNED = {"intake", "corpus_loaded"}


@dataclass(frozen=True)
class Thresholds:
    max_hold_rate: float = 0.30          # share of cases that end in HOLD ...
    min_cases_for_rates: int = 10        # ... once there are enough cases to speak of a rate
    max_refusals_per_case: int = 3       # one case that keeps hitting the gate
    max_messages_per_hour: int = 8       # warn before the gate's hard limit of 10
    max_invalid_verdicts: int = 3        # model output that never parsed
    max_model_calls_per_case: int = 4    # 6 is the hard cap in AuditedLLM; warn before it


def load_markers(path: Path) -> list[str]:
    if not Path(path).exists():
        return []
    return [ln.strip() for ln in Path(path).read_text(encoding="utf-8").splitlines() if ln.strip()]


class AbuseMonitor:
    def __init__(self, audit: AuditLog, thresholds: Thresholds = Thresholds(), markers: list[str] | None = None):
        self.audit, self.t, self.markers = audit, thresholds, list(markers or [])

    def canary_hits(self) -> list[dict]:
        """Rows that contain a planted marker. The marker is reported by number, not repeated."""
        hits = []
        for r in self.audit.rows():
            if r["event"] in _NOT_SCANNED:
                continue
            for i, m in enumerate(self.markers):
                if m in r["payload"]:
                    hits.append({"seq": r["seq"], "event": r["event"], "case_id": r["case_id"], "marker": i})
        return hits

    def alerts(self) -> list[dict]:
        rows = self.audit.rows()
        out: list[dict] = []
        verdicts = [(r, json.loads(r["payload"])) for r in rows if r["event"] == "verdict_checked"]

        n = len(verdicts)
        holds = sum(1 for _, v in verdicts if v.get("status") == "hold")
        if n >= self.t.min_cases_for_rates and holds / n > self.t.max_hold_rate:
            out.append({"alert": "hold_rate", "value": round(holds / n, 3), "limit": self.t.max_hold_rate})

        refused = Counter(r["case_id"] for r in rows if r["event"] == "gate_refused")
        for case_id, c in refused.items():
            if c > self.t.max_refusals_per_case:
                out.append({"alert": "refusals_per_case", "case_id": case_id, "value": c,
                            "limit": self.t.max_refusals_per_case})

        overruns = sum(1 for r in rows if r["event"] == "gate_refused"
                       and json.loads(r["payload"]).get("reason", "").startswith(("exceeds", "max_notify")))
        if overruns:
            out.append({"alert": "limit_overruns", "value": overruns})

        times = sorted(r["ts"] for r in rows if r["event"] == "notify_queued")
        busiest = max((sum(1 for u in times if t <= u < t + 3600) for t in times), default=0)
        if busiest > self.t.max_messages_per_hour:
            out.append({"alert": "message_volume", "value": busiest, "limit": self.t.max_messages_per_hour})

        invalid = sum(1 for r in rows if r["event"] == "verdict_invalid")
        if invalid > self.t.max_invalid_verdicts:
            out.append({"alert": "invalid_verdicts", "value": invalid, "limit": self.t.max_invalid_verdicts})

        # Budgets (layer 6): any hard-cap overrun, and cases that come close to the model-call cap.
        budget = Counter(r["case_id"] for r in rows if r["event"] == "budget_exceeded")
        for case_id, c in budget.items():
            out.append({"alert": "budget_exceeded", "case_id": case_id, "value": c})
        model_calls = Counter(r["case_id"] for r in rows if r["event"] == "model_call")
        for case_id, c in model_calls.items():
            if c > self.t.max_model_calls_per_case:
                out.append({"alert": "model_calls_per_case", "case_id": case_id, "value": c,
                            "limit": self.t.max_model_calls_per_case})

        # Every action must trace to a checked verdict (proposal section 5, "100 % traced").
        for seq in self.audit.untraced_actions():
            out.append({"alert": "untraced_action", "seq": seq})

        

        # A domain that was flagged and is later closed as benign: someone may be teaching the system it is safe.
        flagged: set[str] = set()
        for _, v in verdicts:
            dom = v.get("from_domain") or ""
            if v.get("status") in ("hold", "to_analyst"):
                flagged.add(dom)
            elif v.get("status") == "closed" and dom in flagged:
                out.append({"alert": "safe_after_flagged", "from_domain": dom})
                flagged.discard(dom)      # report once per flip

        for h in self.canary_hits():
            out.append({"alert": "canary_hit", **h})
        return out

    def summary(self) -> dict:
        rows = self.audit.rows()
        events = Counter(r["event"] for r in rows)
        verdicts = [json.loads(r["payload"]) for r in rows if r["event"] == "verdict_checked"]
        statuses = Counter(v.get("status") for v in verdicts)
        by_domain: dict[str, Counter] = {}
        for v in verdicts:
            dom = v.get("from_domain", "")
            by_domain.setdefault(dom, Counter())[v.get("label")] += 1
        n = len(verdicts) or 1
        alerts = self.alerts()
        return {
            "cases": len(verdicts),
            "hold_rate": statuses.get("hold", 0) / n,
            "gate_refusals": events.get("gate_refused", 0),
            "messages_queued": events.get("notify_queued", 0),
            "invalid_verdicts": events.get("verdict_invalid", 0),
            "model_calls": events.get("model_call", 0),
            "budget_overruns": events.get("budget_exceeded", 0),
            "untraced_actions": len(self.audit.untraced_actions()),
            "benign_rate_per_sender_domain": {d: c.get("benign", 0) / sum(c.values()) for d, c in by_domain.items()},
            "canary_hits": sum(1 for a in alerts if a["alert"] == "canary_hit"),
            "markers_loaded": len(self.markers),
            "alerts": alerts,
        }
