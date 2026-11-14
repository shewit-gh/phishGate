"""Read-only rules: look, don't act.

Used twice: as the analysis agent's tool results (untrusted zone) and, re-run
independently, as the verifier's facts (control zone). Same code, two callers,
so a bug here sits on both sides of seam S2.
"""
from .attachment_rules import check_attachments
from .facts import compute_facts, rule_summary
from .header_rules import check_headers
from .url_rules import check_urls
