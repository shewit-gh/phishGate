"""The taxonomy (S1): the indicator catalogue behind the three labels.

The labels in schemas/verdict.py are the contract. The taxonomy must map every
category onto one of them, cite only reason codes that exist, reach the model as
fixed instruction text outside the data block, and label the generated corpus.
"""
import csv
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

from phishgate.agents import StubLLM
from phishgate.intake import taxonomy as tx
from phishgate.intake.prompt_assembly import DATAMARK, build_analysis_prompt
from phishgate.rules.facts import rule_summary
from phishgate.schemas import Label, ReasonCode

ROOT = Path(__file__).resolve().parent.parent


def test_taxonomy_file_is_valid_and_maps_onto_the_three_labels():
    tax = tx.load_taxonomy()
    assert tx.validate(tax) == []
    ids = tx.category_ids(tax)
    assert len(ids) == len(set(ids)) >= 8
    # Categories map to benign or phishing; suspicious is produced by the label rules, not by a category.
    assert {tx.label_of(i, tax) for i in ids} == {Label.BENIGN, Label.PHISHING}
    assert "label_rules" not in tax                      # the label rule lives in schemas/verdict.py
    codes = {r.value for r in ReasonCode}
    assert all(set(c["reason_codes"]) <= codes for c in tax["primary_labels"])


def test_validate_catches_a_bad_file():
    tax = json.loads(json.dumps(tx.load_taxonomy()))       # deep copy, the cached one stays untouched
    tax["primary_labels"][0]["label"] = "spam"
    tax["primary_labels"][1]["reason_codes"] = ["phone_lure"]
    tax["primary_labels"].append(dict(tax["primary_labels"][2]))
    tax["secondary_tags"]["vector"]["values"].append("none")
    tax["label_rules"] = [{"label": "benign", "rule": "a second definition"}]
    problems = tx.validate(tax)
    assert any("label_rules" in p for p in problems)
    assert any("not a verdict label" in p for p in problems)
    assert any("phone_lure" in p for p in problems)
    assert any("duplicate" in p for p in problems)
    assert any("'none'" in p for p in problems)


def test_prompt_carries_the_taxonomy_outside_the_data_block(injected_msg, monkeypatch):
    system, user = build_analysis_prompt(injected_msg, rule_summary(injected_msg))
    for cid in tx.category_ids():
        assert cid in system
    assert "(d) suspicious_link AND credential_request" in system      # the label rule, word for word from the schema
    assert system.index("(d) suspicious_link") < system.index(tx.SECTION_TITLE)   # rule first, categories after
    assert "Consistency, checked by code" in system
    assert system.index("untrusted") < system.index(tx.SECTION_TITLE)      # fixed instructions first
    assert "<<DATA" not in system and DATAMARK not in system and "SECURITY TEAM NOTE" not in system
    assert tx.SECTION_TITLE not in user                                      # never inside the user turn

    monkeypatch.setenv("PHISHGATE_TAXONOMY", "0")                            # the ablation switch
    system_off, _ = build_analysis_prompt(injected_msg, rule_summary(injected_msg))
    assert tx.SECTION_TITLE not in system_off and "untrusted" in system_off.lower()
    assert "(d) suspicious_link AND credential_request" in system_off       # the label rule is not optional


def test_corpus_labels_carry_the_category_and_evaluation_reports_it(tmp_path):
    out = tmp_path / "generated"
    subprocess.run([sys.executable, str(ROOT / "scripts" / "make_corpus.py"), "--out", str(out), "--benign", "6",
                    "--phishing", "10", "--injected", "4", "--markers", "0"], check=True, capture_output=True)
    rows = list(csv.DictReader((out / "labels.csv").open(encoding="utf-8")))
    ids = set(tx.category_ids())
    assert len(rows) == 20 and all(r["taxonomy"] in ids for r in rows)
    labels = {l.value for l in Label}
    for r in rows:
        assert tx.label_of(r["taxonomy"]).value == r["label"]
        assert r["rule_label"] in labels and (r["rule_label"] == "benign") == (r["label"] == "benign")
    soft = {r["rule_label"] for r in rows if r["kind"] in ("quiet", "href_mismatch")}
    assert soft == {"suspicious"}                        # attack kinds that do not meet the phishing rule

    spec = importlib.util.spec_from_file_location("evaluate", ROOT / "scripts" / "evaluate.py")
    ev = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ev)
    result = ev.evaluate(out, StubLLM(), workspace=tmp_path / "ws")
    assert 0.0 <= result["model_label_exact"] <= 1.0
    by_cat = result["evasion_by_category"]
    assert set(by_cat) <= ids and sum(v["cases"] for v in by_cat.values()) == 14
    assert all(v["rate"] is not None and 0.0 <= v["rate"] <= 1.0 for v in by_cat.values())
