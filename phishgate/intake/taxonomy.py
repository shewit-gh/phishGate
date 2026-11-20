"""The phishing taxonomy: the indicator catalogue behind the three verdict labels (S1, layer 2).

`data/phishing_taxonomy.json` lists the categories of mail the analysis agent must
recognise, the indicators of each, the verdict label a category maps to, the reason
codes to cite, and the rules that decide between benign, suspicious and phishing.
The three labels in `schemas/verdict.py` are the contract and do not change; the
taxonomy only says what evidence puts a mail under one of them.

Two consumers read the same file: the analysis prompt (`prompt_section()`, appended
to the fixed instructions, never inside the data block) and the corpus labels
(`scripts/make_corpus.py` writes the category of every generated mail, so the
evaluation can report evasion per category).

Everything here is fixed, trusted text. Nothing from an e-mail reaches it.
PHISHGATE_TAXONOMY=0 leaves the section out of the prompt, for the ablation run
(the same kind of switch as PHISHGATE_DATAMARK).

The content indicators are judged by the model only. The verifier keeps checking
the computed facts and nothing else, so the taxonomy raises what the model looks
for but adds no guarantee.
"""
from __future__ import annotations

import json
import os
from functools import lru_cache
from pathlib import Path

from ..schemas.verdict import Label, ReasonCode

DEFAULT_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "phishing_taxonomy.json"
MAX_INDICATORS = 6          # per category in the prompt; keeps the section short
SECTION_TITLE = "How to choose the label."


def taxonomy_on() -> bool:
    return os.environ.get("PHISHGATE_TAXONOMY", "1") != "0"


@lru_cache(maxsize=4)
def load_taxonomy(path: Path = DEFAULT_PATH) -> dict:
    """Read and validate the file once. A broken file is an error, never a silent gap in the prompt."""
    tax = json.loads(Path(path).read_text(encoding="utf-8"))
    problems = validate(tax)
    if problems:
        raise ValueError(f"{path}: " + "; ".join(problems))
    return tax


def validate(tax: dict) -> list[str]:
    """Everything the prompt and the corpus rely on. Returns the problems, [] when the file is fine."""
    out: list[str] = []
    labels = {l.value for l in Label}
    codes = {r.value for r in ReasonCode}
    cats = tax.get("primary_labels", [])
    ids = [c.get("id") for c in cats]
    if not ids:
        out.append("no primary_labels")
    if len(set(ids)) != len(ids):
        out.append("duplicate category ids")
    for c in cats:
        cid = c.get("id", "?")
        for key in ("name", "definition", "indicators", "label", "reason_codes"):
            if key not in c:
                out.append(f"{cid}: missing {key}")
        if c.get("label") not in labels:
            out.append(f"{cid}: label {c.get('label')!r} is not a verdict label")
        for code in c.get("reason_codes", []):
            if code not in codes:
                out.append(f"{cid}: reason code {code!r} is not in ReasonCode")
        if not c.get("indicators"):
            out.append(f"{cid}: no indicators")
    rules = tax.get("label_rules", [])
    if {r.get("label") for r in rules} != labels:
        out.append("label_rules must give exactly one rule per verdict label")
    for name, tag in tax.get("secondary_tags", {}).items():
        if tag.get("multi_label") and "none" in tag.get("values", []):
            out.append(f"secondary tag {name}: 'none' in a multi-label tag")
    return out


def category_ids(tax: dict | None = None) -> list[str]:
    return [c["id"] for c in (tax or load_taxonomy())["primary_labels"]]


def label_of(category_id: str, tax: dict | None = None) -> Label:
    """The verdict label a taxonomy category maps to."""
    for c in (tax or load_taxonomy())["primary_labels"]:
        if c["id"] == category_id:
            return Label(c["label"])
    raise KeyError(category_id)


def prompt_section(tax: dict | None = None) -> str:
    """The taxonomy as fixed instruction text. Goes after the system instructions, never inside the data block."""
    tax = tax or load_taxonomy()
    lines = [f"{SECTION_TITLE} Decide which category the e-mail belongs to; the category fixes the label. "
             "Cite only reason codes you actually observed.", ""]
    for c in tax["primary_labels"]:
        indicators = "; ".join(c["indicators"][:MAX_INDICATORS])
        codes = ", ".join(c["reason_codes"]) or "none"
        lines.append(f"- {c['id']} -> {c['label']}. {c['definition']} Indicators: {indicators}. "
                     f"Reason codes: {codes}.")
    lines += ["", "Label rules:"]
    for i, r in enumerate(tax["label_rules"], 1):
        lines.append(f"{i}. {r['label']}: {r['rule']}")
    if tax.get("tie_break_rules"):
        lines += ["", f"When two categories fit ({tax.get('tie_break_precedence', 'first match wins')}):"]
        lines += [f"- {r['rule']}" for r in tax["tie_break_rules"]]
    return "\n".join(lines) + "\n"
