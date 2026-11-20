"""Intake (S1, boundary B0): the upload is the only place where an attacker's bytes enter.

The plan's size-cap test: a file over 2 MB is refused and leaves nothing behind; a file
under the cap is stored byte for byte with its SHA-256 recorded.
"""
import hashlib

import pytest

from phishgate.intake import ingest
from phishgate.intake.intake import MAX_EML_BYTES

HEAD = b"From: a@b.test\nTo: c@ourcorp.test\nSubject: big\nMessage-ID: <big@b.test>\n\n"


def _mail_of(size: int) -> bytes:
    return HEAD + b"x" * (size - len(HEAD))


def test_oversize_upload_is_refused_and_leaves_no_case(tmp_path):
    big = tmp_path / "big.eml"
    big.write_bytes(_mail_of(MAX_EML_BYTES + 1))
    ws = tmp_path / "ws"
    with pytest.raises(ValueError, match="exceeds"):
        ingest(big, ws)
    assert not (ws / "cases").exists()                 # nothing stored, no half-made case folder


def test_upload_at_the_cap_is_stored_byte_identical(tmp_path):
    raw = _mail_of(MAX_EML_BYTES)                      # exactly the cap is still allowed
    src = tmp_path / "max.eml"
    src.write_bytes(raw)
    case = ingest(src, tmp_path / "ws")
    assert case.raw_path.read_bytes() == raw
    assert case.file_sha256 == hashlib.sha256(raw).hexdigest()
    assert case.raw_path == tmp_path / "ws" / "cases" / case.case_id / "original.eml"
    assert case.message["Subject"] == "big"            # parsed, not interpreted
