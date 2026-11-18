"""One case, the seven steps of proposal section 1, in order.

This is the orchestrator. It owns the budget, calls each zone in turn, and
writes every step to the audit log. It is the only place where S1, S2 and S3
meet, so keep it short and obvious.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .agents import AuditedLLM, LLMClient, ModelBudgetExceeded, VerdictParseError, run_action_agent, run_analysis_agent
from .audit import AuditLog
from .gate import DEFAULT_POLICY, Gate, GateDecision, Policy
from .intake import ingest
from .rules import compute_facts
from .schemas import CaseStatus, CheckedVerdict, Label, Verdict
from .verifier import verify
from .workspace import Workspace, index_message


@dataclass
class CaseResult:
    checked: CheckedVerdict
    decisions: list[GateDecision] = field(default_factory=list)


class PhishGate:
    def __init__(self, workspace_dir: Path, llm: LLMClient, templates_dir: Path, policy: Policy = DEFAULT_POLICY):
        self.workspace_dir = Path(workspace_dir)
        self.ws = Workspace(self.workspace_dir)
        self.audit = AuditLog(self.workspace_dir / "audit.sqlite3")
        self.llm = AuditedLLM(llm, self.audit)   # every model call logged and budgeted (layer 6)
        self.gate = Gate(self.ws, self.audit, policy, Path(templates_dir))

    def run_case(self, eml_path: Path) -> CaseResult:
        # (1) intake: fingerprint and store
        case = ingest(eml_path, self.workspace_dir)
        self.audit.append("intake", case.case_id, {"sha256": case.file_sha256, "source": str(eml_path)})
        self.llm.start_case(case.case_id)
        # The reported mail joins the corpus index, so it can be found and quarantined like any other.
        index_message(self.ws, case.raw_path.read_bytes(), keep_existing=True)

        # (2) analysis agent: untrusted zone, verdict only
        try:
            verdict = run_analysis_agent(case.message, self.llm)
        except(VerdictParseError, ModelBudgetExceeded) as e:
            return self._hold_without_verdict(case, str(e))
        self.audit.append("verdict_raw", case.case_id, verdict.model_dump())

        # (3) verifier: plain code, recompute facts, HOLD on contradiction  -- TRUST BOUNDARY 1
        checked = verify(case.case_id, case.file_sha256, case.message, verdict)
        self.audit.append("verdict_checked", case.case_id, {
            "status": checked.status.value, "label": verdict.label.value,
            "from_domain": checked.facts.from_domain, "hold_reason": checked.hold_reason})
        if checked.status == CaseStatus.HOLD:
            self._queue_hold(checked)
            return CaseResult(checked)
        if checked.status == CaseStatus.CLOSED:
            return CaseResult(checked)

        # (4) action agent: control zone, sees the checked verdict only
        try:
            proposals = run_action_agent(checked, self.llm)
        except ModelBudgetExceeded:
            proposals = []   # budget_exceeded is already in the log; nothing is proposed
        self.audit.append("proposals", case.case_id, {"proposals": [p.model_dump() for p in proposals]})

        # (5)+(6) gate checks limits and runs tools  -- TRUST BOUNDARY 2
        decisions = self.gate.run(checked, proposals)

        # (7) human approval happens later, through the analyst queue (cli: approve / reject)
        return CaseResult(checked, decisions)

    def _queue_hold(self, checked: CheckedVerdict) -> None:
        """Figure 1: a HOLD case goes to the analyst queue. No tool runs for it."""
        item_id = self.ws.queue_hold_review(checked.case_id, checked.hold_reason or "")
        self.audit.append("hold_queued", checked.case_id, {"item_id": item_id, "hold_reason": checked.hold_reason})

    def _hold_without_verdict(self, case, error: str) -> CaseResult:
        """The model never produced a valid Verdict: fail closed as HOLD instead of crashing.

        `CheckedVerdict` needs a `Verdict`, so code writes a placeholder (label
        suspicious, confidence 0, claims copied from the recomputed facts). It is
        logged as `verdict_invalid`, never as `verdict_raw`, and the case stops.
        """
        self.audit.append("verdict_invalid", case.case_id, {"error": error[:300]})
        facts = compute_facts(case.message)
        placeholder = Verdict(label=Label.SUSPICIOUS, reasons=[],
                              sender_auth_failed=facts.sender_auth == "fail",
                              suspicious_links=facts.suspicious_links,
                              dangerous_attachment=facts.dangerous_attachment, confidence=0.0)
        checked = CheckedVerdict(case_id=case.case_id, file_sha256=case.file_sha256, verdict=placeholder,
                                 facts=facts, status=CaseStatus.HOLD,
                                 hold_reason="analysis agent produced no valid verdict")
        self.audit.append("verdict_checked", case.case_id, {
            "status": checked.status.value, "label": None,
            "from_domain": facts.from_domain, "hold_reason": checked.hold_reason})
        self._queue_hold(checked)
        return CaseResult(checked)
