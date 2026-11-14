"""Fixed limits (defence layer 4). Owner: Junhee. Numbers come from proposal section 4."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Policy:
    max_tool_calls_per_case: int = 12
    max_actions_per_case: int = 3
    max_notify_per_hour: int = 10
    bulk_quarantine_threshold: int = 5   # more than this -> needs human approval
    allowed_templates: tuple[str, ...] = ("phishing_warning", "hold_notice", "benign_closed")


DEFAULT_POLICY = Policy()
