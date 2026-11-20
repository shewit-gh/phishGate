"""Workspace (Junhee): corpus loader, quarantine as a reversible file move, analyst commands."""
from phishgate.cli import main
from phishgate.tools import quarantine
from phishgate.workspace import Workspace, load_corpus, message_id_of

from .conftest import SAMPLES


def test_load_corpus_indexes_every_sample(tmp_path):
    ws = Workspace(tmp_path)
    out = load_corpus(ws, SAMPLES)
    assert out == {"loaded": len(list(SAMPLES.glob("*.eml"))), "skipped": []}
    hits = ws.search_sender("IT-Helpdesk@ourcorp-support.test")          # case-insensitive
    assert [h["recipient"] for h in hits] == ["minji.park@ourcorp.test", "junho.lee@ourcorp.test"]
    assert load_corpus(ws, SAMPLES)["loaded"] == out["loaded"]           # loading twice does not duplicate rows
    assert ws.db.execute("SELECT COUNT(*) FROM corpus").fetchone()[0] == out["loaded"]


def test_message_id_falls_back_to_a_hash():
    assert message_id_of(b"From: a@b.test\nMessage-ID: <abc@b.test>\n\nhi\n") == "abc@b.test"
    assert message_id_of(b"From: a@b.test\n\nno id header\n").startswith("sha256:")
    assert message_id_of(b"From: a@b.test\nMessage-ID: <../../etc x>\n\nhi\n").startswith("sha256:")


def test_quarantine_moves_the_working_copy_and_release_restores_it(tmp_path):
    ws = Workspace(tmp_path)
    load_corpus(ws, SAMPLES)
    src = SAMPLES / "injected_reset.eml"
    mid = message_id_of(src.read_bytes())
    name = ws.file_key(mid)
    assert (ws.corpus_dir / name).exists()

    assert quarantine.quarantine(ws, "case_x", [mid])["count"] == 1
    assert not (ws.corpus_dir / name).exists() and (ws.quarantine_dir / name).exists()
    assert ws.quarantined_ids() == [mid]

    assert quarantine.release(ws, "analyst", [mid])["count"] == 1
    assert (ws.corpus_dir / name).read_bytes() == src.read_bytes()       # byte-identical after the round trip
    assert ws.quarantined_ids() == []
    assert src.exists()                                                  # the source folder is never touched


def test_cli_load_corpus_and_release(tmp_path, capsys):
    ws_dir = str(tmp_path / "ws")
    assert main(["--workspace", ws_dir, "load-corpus", str(SAMPLES)]) == 0
    assert '"loaded": 12' in capsys.readouterr().out
    mid = message_id_of((SAMPLES / "phish_punycode_ko.eml").read_bytes())
    Workspace(tmp_path / "ws").set_quarantine([mid], True, "case_x")
    assert main(["--workspace", ws_dir, "quarantined"]) == 0
    assert mid in capsys.readouterr().out
    assert main(["--workspace", ws_dir, "release", mid]) == 0
    assert Workspace(tmp_path / "ws").quarantined_ids() == []
    assert main(["--workspace", ws_dir, "audit", "--verify"]) == 0
    assert "analyst_release" in capsys.readouterr().out
