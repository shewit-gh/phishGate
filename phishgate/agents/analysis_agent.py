"""Step 2: analysis agent (UNTRUSTED ZONE). Reads the e-mail, outputs a Verdict only.

It has read-only rule results and no action tools. Its output is parsed
strictly; anything that is not a valid `Verdict` is retried, then fails the
case. Budget: at most MAX_CALLS model calls per case, enforced here by the
orchestrator, not by the model.
"""
from __future__ import annotations

import json

from pydantic import ValidationError

from ..intake.prompt_assembly import build_analysis_prompt
from ..rules.facts import rule_summary
from ..schemas.verdict import Verdict
from .llm_client import LLMClient

MAX_CALLS = 3


class VerdictParseError(Exception):
    pass


def run_analysis_agent(msg, llm: LLMClient, analyst_note: str | None = None) -> Verdict:
    system, user = build_analysis_prompt(msg, rule_summary(msg), analyst_note)
    last_err: Exception | None = None
    for _ in range(MAX_CALLS):
        raw = llm.complete(system, user)
        try:
            return Verdict.model_validate(json.loads(raw))
        except (json.JSONDecodeError, ValidationError) as e:
            last_err = e
            user += "\n\nYour previous output was not valid. Output only the JSON object."
    raise VerdictParseError(f"no valid verdict after {MAX_CALLS} calls: {last_err}")
