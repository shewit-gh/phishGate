"""Fixed limits (defence layer 4). Numbers come from proposal section 4."""
from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Mapping

# Which message template may be used for which verdict label. A "no indicator
# found" message on a phishing case is exactly what an attacker wants, so the
# gate refuses any template that does not match the checked label.
_TEMPLATES_BY_LABEL: Mapping[str, tuple[str, ...]] = MappingProxyType({
    "phishing": ("phishing_warning",),
    "suspicious": ("hold_notice",),
    "benign": ("benign_closed",),
})


@dataclass(frozen=True)
class Policy:
    max_tool_calls_per_case: int = 12    # every tool the gate runs for one case, across all rounds
    max_actions_per_case: int = 3        # proposals accepted from one action-agent round
    max_notify_per_hour: int = 10
    bulk_quarantine_threshold: int = 5   # more than this -> needs human approval
    allowed_templates: tuple[str, ...] = ("phishing_warning", "hold_notice", "benign_closed")
    templates_by_label: Mapping[str, tuple[str, ...]] = field(default=_TEMPLATES_BY_LABEL)


DEFAULT_POLICY = Policy()
