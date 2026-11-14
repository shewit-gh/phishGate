"""ABUSE MONITOR: SQL over the audit log. Owner: Diva (defence layer 6).

Watches (proposal section 4, layer 6): safe-rate per sender domain, HOLD rate,
limit overruns, message volume, canary-marker hits. Detection after the fact,
not prevention. Lab 5 adds the rate limit, cost cap and incident runbook on top.

TODO (Diva): thresholds, time windows, canary marker list in data/corpus/markers.txt.
"""
from __future__ import annotations

import json
from collections import Counter

from .audit_log import AuditLog


class AbuseMonitor:
    def __init__(self, audit: AuditLog):
        self.audit = audit

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
        return {
            "cases": len(verdicts),
            "hold_rate": statuses.get("hold", 0) / n,
            "gate_refusals": events.get("gate_refused", 0),
            "messages_queued": events.get("notify_queued", 0),
            "benign_rate_per_sender_domain": {d: c.get("benign", 0) / sum(c.values()) for d, c in by_domain.items()},
            "canary_hits": events.get("canary_hit", 0),
        }
