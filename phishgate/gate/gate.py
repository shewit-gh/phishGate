"""Step 5: the gate. The ONLY component that calls tools. Seam S3.

TRUST BOUNDARY 2: no AI model holds a key. The gate receives typed proposals,
counts them, checks them against `Policy` and the template allow-lists, and
either runs the tool, queues it for human approval, or refuses and logs.

Seam test S3 (tests/test_seam_s3.py): a fourth action, or a notify field not on
the allow-list, must be refused by the gate and logged.

What the gate checks, in order:
  * the case is TO_ANALYST (HOLD and CLOSED cases get no action at all);
  * at most `max_actions_per_case` proposals per round, and at most
    `max_tool_calls_per_case` tool calls per case over all rounds (counted
    from the audit log, so a restart or a replay cannot reset the budget);
  * notify: template allowed, template matches the checked label, field names
    on the allow-list, and field VALUES equal to what the gate derives itself
    from the checked verdict. The model's values are never written into a
    message, so no attacker-written string can reach one (threat T2);
  * quarantine: every id must exist in the corpus AND be a mail from the
    sender of this case, otherwise nothing is done. A reported e-mail can
    therefore never cause someone else's mail to be quarantined;
  * search_sender: only the sender of this case may be searched.
The sender is `Facts.from_address`, recomputed by code from the stored file.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from ..audit.audit_log import AuditLog
from ..schemas.proposal import ActionProposal, NotifyArgs, QuarantineArgs, SearchSenderArgs
from ..schemas.verdict import CaseStatus, CheckedVerdict
from ..tools import notify, quarantine, search_sender
from ..workspace.db import Workspace
from .policy import Policy

# Audit events that mean "the gate ran a tool". The per-case budget counts these.
TOOL_CALL_EVENTS = ("notify_queued", "quarantine_queued", "quarantine_executed", "search_sender_executed")

# The sender domain comes from the From header, which the attacker writes. It is
# only allowed into a message if it has the shape of a plain host name.
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$")


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
        if checked.status != CaseStatus.TO_ANALYST:
            reason = f"case is {checked.status.name}: no actions allowed"
            return [self._refuse(checked, p, reason) for p in proposals]
        calls = self._tool_calls_so_far(checked.case_id)
        for i, p in enumerate(proposals):
            if i >= self.policy.max_actions_per_case:
                decisions.append(self._refuse(
                    checked, p, f"exceeds max_actions_per_case={self.policy.max_actions_per_case}"))
                continue
            if calls >= self.policy.max_tool_calls_per_case:
                decisions.append(self._refuse(
                    checked, p, f"exceeds max_tool_calls_per_case={self.policy.max_tool_calls_per_case}"))
                continue
            d = self._check_and_execute(checked, p)
            if d.outcome != "refused":
                calls += 1
            decisions.append(d)
        return decisions

    def _tool_calls_so_far(self, case_id: str) -> int:
        """Tool calls already made for this case, read back from the audit log."""
        return sum(1 for r in self.audit.rows(case_id) if r["event"] in TOOL_CALL_EVENTS)

    def _trusted_fields(self, checked: CheckedVerdict) -> dict[str, str]:
        """Values the gate is willing to put into a message. None of them comes from a model."""
        trusted = {"case_id": checked.case_id}
        domain = checked.facts.from_domain.strip().lower()
        if _DOMAIN_RE.match(domain):
            trusted["sender_domain"] = domain
        return trusted

    def _refuse(self, checked: CheckedVerdict, p: ActionProposal, reason: str) -> GateDecision:
        self.audit.append("gate_refused", checked.case_id, {"proposal": p.model_dump(), "reason": reason})
        return GateDecision(p, "refused", reason)

    def _check_and_execute(self, checked: CheckedVerdict, p: ActionProposal) -> GateDecision:
        if isinstance(p, NotifyArgs):
            allowed = self._template_fields(p.template_id)
            if allowed is None:
                return self._refuse(checked, p, f"template {p.template_id} not allowed")
            label = checked.verdict.label.value
            if p.template_id not in self.policy.templates_by_label.get(label, ()):
                return self._refuse(checked, p, f"template {p.template_id} does not match label {label}")
            extra = set(p.fields) - allowed
            if extra:
                return self._refuse(checked, p, f"fields not on allow-list: {sorted(extra)}")
            trusted = self._trusted_fields(checked)
            unfillable = allowed - set(trusted)
            if unfillable:
                return self._refuse(checked, p, f"no trusted value for fields: {sorted(unfillable)}")
            wrong = sorted(k for k, v in p.fields.items() if v != trusted[k])
            if wrong:   # the reason names the field only: the value may be attacker text
                return self._refuse(checked, p, f"field values do not match the checked verdict: {wrong}")
            if self.ws.notify_count_last_hour() >= self.policy.max_notify_per_hour:
                return self._refuse(checked, p, "max_notify_per_hour reached")
            values = {k: trusted[k] for k in allowed}   # gate-derived values only, never p.fields
            draft = notify.draft(self.ws, checked.case_id, p.template_id, values, self.templates_dir)
            self.audit.append("notify_queued", checked.case_id, draft)
            return GateDecision(p, "queued_for_approval", result=draft)   # every message waits for a human
        if isinstance(p, QuarantineArgs):
            ids = list(dict.fromkeys(p.message_ids))   # drop duplicates, keep order
            known = self.ws.known_message_ids(ids)
            unknown = [m for m in ids if m not in known]
            if unknown:
                return self._refuse(checked, p, f"{len(unknown)} of {len(ids)} message ids are not in the corpus")
            case_sender = checked.facts.from_address
            foreign = [m for m, s in self.ws.senders_of(ids).items() if not case_sender or s != case_sender]
            if foreign:
                return self._refuse(
                    checked, p, f"{len(foreign)} of {len(ids)} message ids are not from the sender of this case")
            if len(ids) > self.policy.bulk_quarantine_threshold:
                q = quarantine.queue_bulk(self.ws, checked.case_id, ids)
                self.audit.append("quarantine_queued", checked.case_id, q)
                return GateDecision(p, "queued_for_approval", result=q)
            res = quarantine.quarantine(self.ws, checked.case_id, ids)
            self.audit.append("quarantine_executed", checked.case_id, res)
            return GateDecision(p, "executed", result=res)
        if isinstance(p, SearchSenderArgs):
            case_sender = checked.facts.from_address
            if not case_sender or p.sender_address.strip().lower() != case_sender:
                return self._refuse(checked, p, "search_sender is limited to the sender of this case")
            res = search_sender.search(self.ws, case_sender)
            self.audit.append("search_sender_executed", checked.case_id,
                              {"sender": case_sender, "hits": len(res)})
            return GateDecision(p, "executed", result={"hits": res})
        return self._refuse(checked, p, "unknown action")
