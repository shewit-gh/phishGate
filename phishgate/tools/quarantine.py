"""quarantine(ids) / release(ids): flag a working copy, keep the original, reversible, logged."""
from __future__ import annotations


def quarantine(ws, case_id: str, message_ids: list[str]) -> dict:
    moved = ws.set_quarantine(message_ids, True, case_id)
    return {"quarantined": moved, "count": len(moved)}


def release(ws, case_id: str, message_ids: list[str]) -> dict:
    released = ws.set_quarantine(message_ids, False, case_id)
    return {"released": released, "count": len(released)}


def queue_bulk(ws, case_id: str, message_ids: list[str]) -> dict:
    approval_id = ws.queue_bulk_quarantine(case_id, message_ids)
    return {"approval_id": approval_id, "count": len(message_ids)}
