"""HTML to visible text. Used by prompt assembly (what the model reads) and by the URL rules.

A reader sees only the rendered text, so that is what the model gets: comments,
scripts, styles and anything hidden with CSS are dropped. Hidden text is where
injected instructions usually sit. Its presence is reported as a flag (it is a
signal in itself); its content is never passed on.

Standard library only (`html.parser`), no network, nothing is executed.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from html.parser import HTMLParser

_VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "track", "wbr"}
_NEVER_SHOWN = {"script", "style", "head", "title", "template", "noscript"}
_BLOCK = {"p", "div", "br", "tr", "li", "h1", "h2", "h3", "h4", "h5", "h6", "table", "section", "blockquote"}
_HIDDEN_STYLE = re.compile(
    r"display\s*:\s*none|visibility\s*:\s*hidden|"
    r"(?:font-size|opacity|(?:max-)?height|(?:max-)?width)\s*:\s*0(?![.\d])", re.I)


@dataclass
class HtmlView:
    text: str = ""
    links: list[tuple[str, str]] = field(default_factory=list)   # (href, visible anchor text)
    hidden_text: bool = False                                    # non-empty text inside a hidden element
    comments: bool = False                                       # non-empty HTML comment


class _Extractor(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.out: list[str] = []
        self.stack: list[tuple[str, bool]] = []      # (tag, hides its content)
        self.anchor: tuple[str, list[str]] | None = None
        self.view = HtmlView()

    def _hidden(self) -> bool:
        return any(h for _, h in self.stack)

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag in _BLOCK:
            self.out.append("\n")
        if tag in _VOID:
            return
        hides = tag in _NEVER_SHOWN or "hidden" in a or bool(_HIDDEN_STYLE.search(a.get("style") or ""))
        self.stack.append((tag, hides))
        if tag == "a":
            self.anchor = ((a.get("href") or "").strip(), [])

    def handle_endtag(self, tag):
        if tag == "a" and self.anchor is not None:
            href, parts = self.anchor
            text = " ".join("".join(parts).split())
            if href:
                self.view.links.append((href, text))
                if not self._hidden():
                    self.out.append(f" [link: {href}]")
            self.anchor = None
        for i in range(len(self.stack) - 1, -1, -1):  # close the nearest open tag of that name
            if self.stack[i][0] == tag:
                del self.stack[i:]
                break
        if tag in _BLOCK:
            self.out.append("\n")

    def handle_data(self, data):
        if self._hidden():
            if data.strip() and not any(t in ("script", "style", "head", "title") for t, _ in self.stack):
                self.view.hidden_text = True
            return
        self.out.append(data)
        if self.anchor is not None:
            self.anchor[1].append(data)

    def handle_comment(self, data):
        if data.strip():
            self.view.comments = True


def html_view(html: str) -> HtmlView:
    p = _Extractor()
    try:
        p.feed(html)
        p.close()
    except Exception:          # malformed markup: keep what was parsed so far, never crash a rule
        pass
    lines = [" ".join(ln.split()) for ln in "".join(p.out).splitlines()]
    p.view.text = "\n".join(ln for ln in lines if ln)
    return p.view
