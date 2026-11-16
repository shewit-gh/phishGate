"""Domain helpers shared by the header and URL rules: registrable domain, look-alike check.

The organisation's own domains are listed in data/org_domains.txt (one per
line). A host is a look-alike when it is NOT one of those domains but is built
to be read as one: the organisation's name used as a word in another domain
(`ourcorp-support.test`, `ourcorp.evil.test`), a confusable spelling
(`0urcorp.test`, `ourcorp` written with `rn` for `m`), or a one-letter typo.

No network and no public-suffix list in the container, so `registrable()` uses
the last two labels plus a short list of two-level suffixes. Accepted gap.
"""
from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path

ORG_DOMAINS_FILE = Path(__file__).resolve().parents[2] / "data" / "org_domains.txt"

_TWO_LEVEL_SUFFIXES = {"co.kr", "or.kr", "ac.kr", "go.kr", "ne.kr", "re.kr", "co.uk", "org.uk", "ac.uk",
                       "co.jp", "com.au", "com.cn", "com.tw", "com.sg", "com.br"}
_CONFUSABLES = (("rn", "m"), ("vv", "w"), ("0", "o"), ("1", "l"), ("3", "e"), ("5", "s"), ("7", "t"))


def registrable(host: str) -> str:
    """`mail.ourcorp.test` -> `ourcorp.test`; `a.b.co.kr` -> `b.co.kr`."""
    labels = [x for x in host.lower().strip(".").split(".") if x]
    if len(labels) <= 2:
        return ".".join(labels)
    n = 3 if ".".join(labels[-2:]) in _TWO_LEVEL_SUFFIXES else 2
    return ".".join(labels[-n:])


@lru_cache(maxsize=1)
def org_domains() -> tuple[str, ...]:
    if not ORG_DOMAINS_FILE.exists():
        return ()
    lines = (ln.split("#", 1)[0].strip().lower() for ln in ORG_DOMAINS_FILE.read_text(encoding="utf-8").splitlines())
    return tuple(ln for ln in lines if ln)


def _skeleton(name: str) -> str:
    for a, b in _CONFUSABLES:
        name = name.replace(a, b)
    return name


def _edit_distance(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def is_lookalike(host: str, orgs: tuple[str, ...] | None = None) -> bool:
    """True if `host` imitates one of the organisation's domains without being one."""
    host = host.lower().strip(".")
    if not host:
        return False
    orgs = org_domains() if orgs is None else orgs
    reg = registrable(host)
    if reg in orgs:
        return False                                   # the real domain or one of its subdomains
    name = reg.split(".", 1)[0]
    words = set(re.split(r"[-_.]", host))
    for org in orgs:
        org_name = org.split(".", 1)[0]
        if org_name in words:                          # ourcorp-support.test, ourcorp.evil.test
            return True
        if _skeleton(name) == _skeleton(org_name):     # 0urcorp.test, same name under another TLD
            return True
        limit = 2 if len(org_name) >= 8 else 1
        if len(org_name) >= 5 and _edit_distance(name, org_name) <= limit:   # ourcrop.test
            return True
    return False
