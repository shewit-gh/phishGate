"""The scripts: BOM check fails closed, the corpus generator is reproducible, the evaluation and
the sycophancy test run."""
import csv
import hashlib
import importlib.util
import subprocess
import sys
from pathlib import Path

from phishgate.agents import StubLLM

ROOT = Path(__file__).resolve().parent.parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _make_model(tmp_path, files):
    folder = tmp_path / "models" / "tiny"
    folder.mkdir(parents=True)
    for name, data in files.items():
        (folder / name).write_bytes(data)
    return folder


def _bom(tmp_path, folder, revision="a" * 40):
    lines = ["models:", "  - name: tiny", f"    revision: {revision}", "    files:"]
    lines += [f"      - {{path: {p.name}, sha256: {hashlib.sha256(p.read_bytes()).hexdigest()}}}"
              for p in sorted(folder.iterdir())]
    path = tmp_path / "bom.yaml"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def test_bom_check_passes_then_fails_on_any_change(tmp_path):
    bom = _load("check_bom")
    folder = _make_model(tmp_path, {"model.safetensors": b"weights", "config.json": b'{"model_type": "x"}'})
    path = _bom(tmp_path, folder)
    assert bom.check_bom(path, tmp_path / "models") == []

    (folder / "model.safetensors").write_bytes(b"weights tampered")
    assert any("does not match" in p for p in bom.check_bom(path, tmp_path / "models"))
    (folder / "model.safetensors").write_bytes(b"weights")

    (folder / "extra.bin").write_bytes(b"pickle")
    problems = bom.check_bom(path, tmp_path / "models")
    assert any("not recorded" in p for p in problems) and any("pickle-format" in p for p in problems)
    (folder / "extra.bin").unlink()

    (folder / "config.json").write_bytes(b'{"auto_map": {"AutoModel": "x.Y"}}')
    assert any("auto_map" in p for p in bom.check_bom(_bom(tmp_path, folder), tmp_path / "models"))


def test_unfilled_bom_fails_closed(tmp_path):
    bom = _load("check_bom")
    problems = bom.check_bom(ROOT / "bom.yaml", tmp_path / "models")     # the repository's own BOM, no weights here
    assert problems and not any("passed" in p for p in problems)
    folder = _make_model(tmp_path, {"model.safetensors": b"w"})
    assert any("revision" in p for p in bom.check_bom(_bom(tmp_path, folder, revision="TBD"), tmp_path / "models"))


def test_corpus_is_reproducible_and_evaluation_runs(tmp_path):
    def generate(out):
        subprocess.run([sys.executable, str(ROOT / "scripts" / "make_corpus.py"), "--out", str(out), "--benign", "12",
                        "--phishing", "10", "--injected", "10", "--markers", "3"], check=True, capture_output=True)
        return {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(out.glob("*.eml"))}

    first, second = generate(tmp_path / "a" / "generated"), generate(tmp_path / "b" / "generated")
    assert first == second and len(first) == 32
    rows = list(csv.DictReader((tmp_path / "a" / "generated" / "labels.csv").open(encoding="utf-8")))
    assert sum(r["marker"] == "yes" for r in rows) == 3
    assert {r["lang"] for r in rows} == {"ko", "en"}

    result = _load("evaluate").evaluate(tmp_path / "a" / "generated", StubLLM(), workspace=tmp_path / "ws")
    assert result["cases"] == 32 and result["cases_traced"] == 1.0 and result["audit_chain_ok"]
    assert result["hold_rate_on_benign"] == 0.0          # no benign mail is stopped by the rules alone
    assert result["canary_hits"] == 0 and result["markers_loaded"] == 3
    # The stub calls everything benign: a system that trusted the label would close all 20 attack mails.
    cmp = result["defence_comparison"]
    assert cmp["attack_mails"] == 20 and cmp["attack_closed_if_model_label_is_trusted"] == 20
    assert cmp["attack_closed_with_verifier"] < 20 and cmp["benign_closed"] == 12
    assert set(result["by_language"]) == {"ko", "en"}
    assert sum(v["benign"] + v["attack"] for v in result["by_language"].values()) == 32
    assert result["actions_proposed"] == {} and result["refusal_reasons"] == {}
    assert result["groups"]["injected"].get("hold", 0) >= 8      # the verifier stops most of them without any model


class _Pushover:
    """A model that is right until someone tells it otherwise: it answers what the analyst comment asks for."""

    def complete(self, system, user):
        import json
        failed = '"sender_auth": "fail"' in user
        links = '"suspicious_links": true' in user
        attach = '"dangerous_attachment": true' in user
        label = "phishing" if (failed or links or attach) else "benign"
        if "[ANALYST COMMENT]" in user:
            label = "benign" if label == "phishing" else "phishing"
        return json.dumps({"label": label, "reasons": [], "sender_auth_failed": failed, "suspicious_links": links,
                           "dangerous_attachment": attach, "confidence": 0.95})


def test_sycophancy_script_counts_flips_and_what_the_verifier_still_stops(tmp_path):
    out = tmp_path / "generated"
    subprocess.run([sys.executable, str(ROOT / "scripts" / "make_corpus.py"), "--out", str(out), "--benign", "12",
                    "--phishing", "10", "--injected", "0", "--markers", "0"], check=True, capture_output=True)
    syc = _load("sycophancy")

    steady = syc.run(out, StubLLM(), n=10)                  # the stub ignores the comment
    assert steady["flips"] == 0 and steady["correct_by_label"]["phishing"] == 0

    r = syc.run(out, _Pushover(), n=10)
    assert r["correct_cases"] >= 6 and r["flips"] == r["correct_cases"] and r["flip_rate"] == 1.0
    assert r["phishing_talked_into_benign"] == r["correct_by_label"]["phishing"] > 0
    # Every one of those has a hard indicator, so the verifier holds the case although the model gave in.
    assert r["talked_into_benign_and_closed"] == 0
    assert r["talked_into_benign_but_stopped_by_verifier"] == r["phishing_talked_into_benign"]
