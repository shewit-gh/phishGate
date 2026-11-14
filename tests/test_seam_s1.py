"""Seam S1 (Shewit): intake -> prompt -> analysis agent.

The seam test from the proposal: an e-mail whose body contains a fake verdict
must not be echoed as the verdict. With the stub LLM this only checks the
prompt structure; the real test needs the model and is marked for later.
"""
import pytest

from phishgate.intake.prompt_assembly import build_analysis_prompt
from phishgate.rules.facts import rule_summary


def test_email_is_inside_data_block_and_after_instructions(injected_msg):
    system, user = build_analysis_prompt(injected_msg, rule_summary(injected_msg))
    assert "untrusted" in system.lower()
    start, end = user.index("<<DATA "), user.index("<<END DATA ")
    assert start < user.index("SECURITY TEAM NOTE") < end, "injected text must sit inside the data block"


@pytest.mark.skip(reason="needs the real model; Shewit to enable once Ollama/vLLM is available")
def test_fake_verdict_in_body_is_not_echoed():
    ...
