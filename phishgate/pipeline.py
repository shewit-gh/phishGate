"""One case, the seven steps of proposal section 1, in order.

This is the orchestrator. It owns the budget, calls each zone in turn, and
writes every step to the audit log. It is the only place where S1, S2 and S3
meet, so keep it short and obvious.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .agents import LLMClient, run_action_agent, run_analysis_agent
from .audit import AuditLog
from .gate import DEFAULT_POLICY, Gate, GateDecision, Policy
from .intake import ingest
from .schemas import CaseStatus, CheckedVerdict
from .verifier import verify
from .workspace import Workspace


@dataclass
class CaseResult:
    checked: CheckedVerdict
    decisions: list[GateDecision] = field(default_factory=list)


class PhishGate:
    def __init__(self, workspace_dir: Path, llm: LLMClient, templates_dir: Path, policy: Policy = DEFAULT_POLICY):
        self.workspace_dir = Path(workspace_dir)
        self.ws = Workspace(self.workspace_dir)
        self.audit = AuditLog(self.workspace_dir / "audit.sqlite3")
        self.llm = llm
        self.gate = Gate(self.ws, self.audit, policy, Path(templates_dir))

    def run_case(self, eml_path: Path) -> CaseResult:
        # (1) intake: fingerprint and store
        case = ingest(eml_path, self.workspace_dir)
        self.audit.append("intake", case.case_id, {"sha256": case.file_sha256, "source": str(eml_path)})

        # (2) analysis agent: untrusted zone, verdict only
        verdict = run_analysis_agent(case.message, self.llm)
        self.audit.append("verdict_raw", case.case_id, verdict.model_dump())

        # (3) verifier: plain code, recompute facts, HOLD on contradiction  -- TRUST BOUNDARY 1
        checked = verify(case.case_id, case.file_sha256, case.message, verdict)
        self.audit.append("verdict_checked", case.case_id, {
            "status": checked.status.value, "label": verdict.label.value,
            "from_domain": checked.facts.from_domain, "hold_reason": checked.hold_reason})
        if checked.status in (CaseStatus.HOLD, CaseStatus.CLOSED):
            return CaseResult(checked)

        # (4) action agent: control zone, sees the checked verdict only
        proposals = run_action_agent(checked, self.llm)
        self.audit.append("proposals", case.case_id, {"proposals": [p.model_dump() for p in proposals]})

        # (5)+(6) gate checks limits and runs tools  -- TRUST BOUNDARY 2
        decisions = self.gate.run(checked, proposals)

        # (7) human approval happens later, through the analyst queue (cli: approve / reject)
        return CaseResult(checked, decisions)
