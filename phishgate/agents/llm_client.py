"""One local open-weight model, used twice with different instructions.

Planned: Qwen2.5-14B-Instruct (4-bit AWQ) via vLLM or Ollama on the lab GPU,
to be confirmed at the mid-check. The container has no outbound network; the
model server runs on the same host. `StubLLM` lets the whole pipeline run with
no model at all, for tests and for the skeleton.
"""
from __future__ import annotations

import json
from typing import Protocol
from urllib import request


class LLMClient(Protocol):
    def complete(self, system: str, user: str) -> str: ...


class StubLLM:
    """Returns canned JSON. Tests use `queue` to script the model's behaviour."""

    def __init__(self, queue: list[str] | None = None, default: str | None = None):
        self.queue = list(queue or [])
        self.default = default or json.dumps({
            "label": "benign", "reasons": ["none"], "sender_auth_failed": False,
            "suspicious_links": False, "dangerous_attachment": False, "confidence": 0.5})
        self.calls: list[tuple[str, str]] = []

    def complete(self, system: str, user: str) -> str:
        self.calls.append((system, user))
        return self.queue.pop(0) if self.queue else self.default


class OllamaClient:
    """Minimal client for a local Ollama server (default http://127.0.0.1:11434)."""

    def __init__(self, model: str = "qwen2.5:14b", base_url: str = "http://127.0.0.1:11434", timeout: int = 120):
        self.model, self.base_url, self.timeout = model, base_url, timeout

    def complete(self, system: str, user: str) -> str:
        payload = {
            "model": self.model, "stream": False, "format": "json",
            "options": {"temperature": 0},
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
        }
        req = request.Request(f"{self.base_url}/api/chat", data=json.dumps(payload).encode(),
                              headers={"Content-Type": "application/json"})
        with request.urlopen(req, timeout=self.timeout) as resp:
            return json.loads(resp.read())["message"]["content"]
