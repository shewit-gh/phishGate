"""notify(template_id, fields): fill a fixed template, put the draft in the analyst queue.

No free text, no links from the e-mail. Approved drafts are written to
outbox/ as files; nothing is ever sent.
"""
from __future__ import annotations

import json
from pathlib import Path


def draft(ws, case_id: str, template_id: str, fields: dict[str, str], templates_dir: Path) -> dict:
    tpl = json.loads((templates_dir / f"{template_id}.json").read_text(encoding="utf-8"))
    body = tpl["body"]
    for k in tpl["fields"]:
        body = body.replace("{" + k + "}", fields.get(k, ""))   # missing field -> blank, never model text
    draft_id = ws.queue_message(case_id, template_id, tpl["subject"], body)
    return {"draft_id": draft_id, "template_id": template_id, "subject": tpl["subject"], "body": body}
