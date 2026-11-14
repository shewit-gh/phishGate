"""Attachment rules: dangerous extensions, macros, type mismatch. Owner: Shewit.

TODO: libmagic for real type detection, oletools (olevba) for macro detection.
Skeleton uses the file extension and declared content type only.
"""
from __future__ import annotations

from email.message import EmailMessage
from pathlib import PurePosixPath

DANGEROUS_EXT = {".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".ps1", ".hta", ".jar",
                 ".docm", ".xlsm", ".pptm", ".iso", ".lnk"}


def check_attachments(msg: EmailMessage) -> dict:
    items = []
    for part in msg.iter_attachments():
        name = part.get_filename() or ""
        ext = PurePosixPath(name.lower()).suffix
        items.append({
            "filename": name[:120],
            "content_type": part.get_content_type(),
            "dangerous": ext in DANGEROUS_EXT,
        })
    return {
        "attachment_count": len(items),
        "dangerous_attachment": any(i["dangerous"] for i in items),
        "attachments": items,
    }
