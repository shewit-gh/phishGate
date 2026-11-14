"""Step 5: the gate. The ONLY component that calls tools. Owner: Junhee (S3).

TRUST BOUNDARY 2: no AI model holds a key. The gate receives typed proposals,
counts them, checks them against `Policy` and the template allow-lists, and
either runs the tool, queues it for human approval, or refuses and logs.

Seam test S3 (tests/test_seam_s3.py): a fourth action, or a notify field not on
the allow-list, must be refused by the gate and logged.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from ..audit.audit_log import AuditLog
from ..schemas.proposal import ActionProposal, NotifyArgs, QuarantineArgs, SearchSenderArgs
from ..schemas.verdict import CaseStatus, CheckedVerdict
from ..tools import notify, quarantine, search_sender
from ..workspace.db import Workspace
from .policy import Policy


@dataclass
class GateDecision:
    proposal: ActionProposal
    outcome: str                 # "executed" | "queued_for_approval" | "refused"
    reason: str = ""
    result: dict = field(default_factory=dict)


class Gate:
    def __init__(self, ws: Workspace, audit: AuditLog, policy: Policy, templates_dir: Path):
        self.ws, self.audit, self.policy, self.templates_dir = ws, audit, policy, templates_dir

    def _template_fields(self, template_id: str) -> set[str] | None:
        p = self.templates_dir / f"{template_id}.json"
        if template_id not in self.policy.allowed_templates or not p.exists():
            return None
        return set(json.loads(p.read_text(encoding="utf-8"))["fields"])

    def run(self, checked: CheckedVerdict, proposals: list[ActionProposal]) -> list[GateDecision]:
        decisions: list[GateDecision] = []
        if checked.status == CaseStatus.HOLD:
            return [self._refuse(checked, p, "case is HOLD: no actions allowed") for p in proposals]
        for i, p in enumerate(proposals):
            if i >= self.policy.max_actions_per_case:
                decisions.append(self._refuse(
                    checked, p, f"exceeds max_actions_per_case={self.policy.max_actions_per_case}"))
                continue
            decisions.append(self._check_and_execute(checked, p))
        return decisions

    def _refuse(self, checked: CheckedVerdict, p: ActionProposal, reason: str) -> GateDecision:
        self.audit.append("gate_refused", checked.case_id, {"proposal": p.model_dump(), "reason": reason})
        return GateDecision(p, "refused", reason)

    def _check_and_execute(self, checked: CheckedVerdict, p: ActionProposal) -> GateDecision:
        if isinstance(p, NotifyArgs):
            allowed = self._template_fields(p.template_id)
            if allowed is None:
                return self._refuse(checked, p, f"template {p.template_id} not allowed")
            extra = set(p.fields) - allowed
            if extra:
                return self._refuse(checked, p, f"fields not on allow-list: {sorted(extra)}")
            if self.ws.notify_count_last_hour() >= self.policy.max_notify_per_hour:
                return self._refuse(checked, p, "max_notify_per_hour reached")
            draft = notify.draft(self.ws, checked.case_id, p.template_id, p.fields, self.templates_dir)
            self.audit.append("notify_queued", checked.case_id, draft)
            return GateDecision(p, "queued_for_approval", result=draft)   # every message waits for a human
        if isinstance(p, QuarantineArgs):
            if len(p.message_ids) > self.policy.bulk_quarantine_threshold:
                q = quarantine.queue_bulk(self.ws, checked.case_id, p.message_ids)
                self.audit.append("quarantine_queued", checked.case_id, q)
                return GateDecision(p, "queued_for_approval", result=q)
            res = quarantine.quarantine(self.ws, checked.case_id, p.message_ids)
            self.audit.append("quarantine_executed", checked.case_id, res)
            return GateDecision(p, "executed", result=res)
        if isinstance(p, SearchSenderArgs):
            res = search_sender.search(self.ws, p.sender_address)
            self.audit.append("search_sender_executed", checked.case_id,
                              {"sender": p.sender_address, "hits": len(res)})
            return GateDecision(p, "executed", result={"hits": res})
        return self._refuse(checked, p, "unknown action")
