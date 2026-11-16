"""Step 1: intake. Seam S1.

Records a SHA-256 fingerprint of the uploaded .eml and stores it in the case
folder. The file is DATA: nothing in it is executed or interpreted here.
"""
from __future__ import annotations

import email
import hashlib
import secrets
from dataclasses import dataclass
from email import policy
from email.message import EmailMessage
from pathlib import Path

MAX_EML_BYTES = 2 * 1024 * 1024  # 2 MB cap


@dataclass(frozen=True)
class Case:
    case_id: str
    file_sha256: str
    raw_path: Path          # the stored, byte-identical copy of the upload
    message: EmailMessage   # parsed with the default policy


def ingest(eml_path: Path, workspace_dir: Path) -> Case:
    """Fingerprint and store one uploaded .eml. Raises on oversize input."""
    raw = Path(eml_path).read_bytes()
    if len(raw) > MAX_EML_BYTES:
        raise ValueError(f"upload exceeds {MAX_EML_BYTES} bytes")
    sha = hashlib.sha256(raw).hexdigest()
    case_id = f"case_{secrets.token_hex(4)}"
    case_dir = workspace_dir / "cases" / case_id
    case_dir.mkdir(parents=True, exist_ok=False)
    raw_path = case_dir / "original.eml"
    raw_path.write_bytes(raw)
    msg = email.message_from_bytes(raw, policy=policy.default)
    return Case(case_id=case_id, file_sha256=sha, raw_path=raw_path, message=msg)
