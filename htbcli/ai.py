from __future__ import annotations
import os
from dataclasses import dataclass
from enum import Enum
from typing import Optional

import requests

try:
    from openai import OpenAI
except Exception:  # pragma: no cover
    OpenAI = None  # type: ignore


class Provider(str, Enum):
    OPENAI = "openai"
    OLLAMA = "ollama"
    STUB = "stub"


@dataclass
class AIConfig:
    provider: Provider
    model: str = "gpt-4o-mini"
    base_url: Optional[str] = None


class AIClient:
    def __init__(self, config: AIConfig):
        self.config = config
        self._client = None
        if config.provider == Provider.OPENAI and OpenAI is not None:
            self._client = OpenAI()

    def ask(self, system: str, question: str) -> str:
        if self.config.provider == Provider.OPENAI and self._client is not None:
            try:
                resp = self._client.chat.completions.create(
                    model=self.config.model,
                    messages=[
                        {"role": "system", "content": system},
                        {"role": "user", "content": question},
                    ],
                    temperature=0.2,
                )
                return (resp.choices[0].message.content or "").strip()
            except Exception as e:
                return f"[OpenAI error] {e}"
        elif self.config.provider == Provider.OLLAMA:
            try:
                base = self.config.base_url or os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
                url = f"{base.rstrip('/')}/api/chat"
                payload = {
                    "model": self.config.model,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": question},
                    ],
                    "stream": False,
                    "options": {"temperature": 0.2},
                }
                r = requests.post(url, json=payload, timeout=120)
                r.raise_for_status()
                data = r.json()
                msgs = data.get("message", {}).get("content") or data.get("messages", [{}])[-1].get("content")
                return (msgs or "").strip()
            except Exception as e:
                return f"[Ollama error] {e}"
        else:
            return "AI provider not configured. Set OPENAI_API_KEY or run Ollama locally and set OLLAMA_BASE_URL."
