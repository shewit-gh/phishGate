"""Attachment rules: dangerous extensions, macros, type mismatch.

Standard library only. An attachment is never opened, run or unpacked: the
code looks at the file name, at the first bytes, and (for ZIP-based files) at
the list of member names. Nothing is decompressed, so a zip bomb costs nothing.

An attachment is dangerous if any of these holds (the `why` codes below):

  extension          the name ends in an executable / macro-enabled / disk-image suffix
  executable_content the bytes start like a Windows program, a shortcut or a disk image,
                     whatever the name says
  macro              an Office file that carries a VBA project (new or old format)
  archive_member     a ZIP that holds a member with a dangerous suffix

Limits: `macro` says a VBA project is present, not what it does (olevba would).
An encrypted archive is reported (`encrypted_archive`) but its members cannot be
judged, and nested archives are not followed.
"""
from __future__ import annotations

import io
import zipfile
from email.message import EmailMessage
from pathlib import PurePosixPath

DANGEROUS_EXT = {".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".ps1", ".hta", ".jar",
                 ".docm", ".xlsm", ".pptm", ".iso", ".lnk"}

MAX_INSPECT_BYTES = 20 * 1024 * 1024      # larger attachments are judged by name only
MAX_ZIP_MEMBERS = 2000

_MZ = b"MZ"
_LNK = b"\x4c\x00\x00\x00\x01\x14\x02\x00"
_OLE2 = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
_ZIP = b"PK\x03\x04"
_ISO_AT, _ISO = 0x8001, b"CD001"
# Directory entries of the old Office format are UTF-16LE; a file with macros has this storage.
_OLE_VBA = "_VBA_PROJECT".encode("utf-16-le")


def _payload(part) -> bytes:
    try:
        data = part.get_payload(decode=True)
    except Exception:                      # undecodable part: judge by name only, never crash
        return b""
    return data if isinstance(data, bytes) else b""


def inspect_bytes(name: str, data: bytes) -> list[str]:
    """Reason codes for one attachment. Fixed strings only; nothing from the file is copied out."""
    why: list[str] = []
    ext = PurePosixPath(name.lower()).suffix
    if ext in DANGEROUS_EXT:
        why.append("extension")
    if not data or len(data) > MAX_INSPECT_BYTES:
        return why
    if data.startswith(_MZ) or data.startswith(_LNK) or data[_ISO_AT:_ISO_AT + 5] == _ISO:
        why.append("executable_content")
    elif data.startswith(_OLE2):
        if _OLE_VBA in data:
            why.append("macro")
    elif data.startswith(_ZIP):
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                infos = z.infolist()[:MAX_ZIP_MEMBERS]
        except (zipfile.BadZipFile, ValueError, OSError):
            infos = []
        members = [i.filename.lower() for i in infos]
        if any(PurePosixPath(m).name == "vbaproject.bin" for m in members):
            why.append("macro")
        if any(PurePosixPath(m).suffix in DANGEROUS_EXT for m in members):
            why.append("archive_member")
        if any(i.flag_bits & 0x1 for i in infos):
            why.append("encrypted_archive")
    return why


# Reported to the analyst but not enough on its own to call the file dangerous.
_NOT_DANGEROUS_ALONE = {"encrypted_archive"}


def check_attachments(msg: EmailMessage) -> dict:
    items = []
    for part in msg.iter_attachments():
        name = part.get_filename() or ""
        why = inspect_bytes(name, _payload(part))
        items.append({
            "filename": name[:120],
            "content_type": part.get_content_type(),
            "dangerous": any(w not in _NOT_DANGEROUS_ALONE for w in why),
            "why": why,
        })
    return {
        "attachment_count": len(items),
        "dangerous_attachment": any(i["dangerous"] for i in items),
        "attachments": items,
    }
