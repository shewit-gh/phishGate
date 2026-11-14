"""Step 4: action agent (CONTROL ZONE). Same model, other instructions.

Input: the CheckedVerdict ONLY. It never sees e-mail text. Output: a list of
typed ActionProposals, which the gate counts and checks.
TODO (Junhee): prompt wording, template choice logic, parse robustness.
"""
from __future__ import annotations

import json

from pydantic import TypeAdapter, ValidationError

from ..schemas.proposal import ActionProposal
from ..schemas.verdict import CheckedVerdict
from .llm_client import LLMClient

ACTION_SYSTEM = """You are the action agent of PhishGate. You receive a checked verdict
(JSON) about a reported e-mail. You never see the e-mail. Propose at most 3
actions as a JSON list. Allowed actions and arguments:
  {"action":"quarantine","message_ids":[...]}
  {"action":"search_sender","sender_address":"..."}
  {"action":"notify","template_id":"<name>","fields":{...}}
Output only the JSON list."""

_adapter = TypeAdapter(list[ActionProposal])


def run_action_agent(checked: CheckedVerdict, llm: LLMClient) -> list[ActionProposal]:
    raw = llm.complete(ACTION_SYSTEM, checked.model_dump_json())
    try:
        return _adapter.validate_python(json.loads(raw))
    except (json.JSONDecodeError, ValidationError):
        return []  # an unparsable proposal is no proposal; the gate then has nothing to do
