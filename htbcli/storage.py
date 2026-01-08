import os
import json
import time
from pathlib import Path
from typing import Dict, Any, List

DATA_DIR = Path.home() / ".htbcli" / "challenges"


def ensure_data_dir():
    DATA_DIR.mkdir(parents=True, exist_ok=True)


class ChallengeStore:
    def __init__(self):
        ensure_data_dir()
        self.data_dir = DATA_DIR

    def _path(self, name: str) -> Path:
        return self.data_dir / f"{name}.json"

    def exists(self, name: str) -> bool:
        return self._path(name).exists()

    def create(self, name: str, context: Dict[str, Any]):
        context = dict(context)
        context["name"] = name
        context["updated"] = time.strftime("%Y-%m-%d %H:%M:%S")
        with self._path(name).open("w", encoding="utf-8") as f:
            json.dump(context, f, ensure_ascii=False, indent=2)

    def load(self, name: str) -> Dict[str, Any]:
        with self._path(name).open("r", encoding="utf-8") as f:
            return json.load(f)

    def save(self, name: str, context: Dict[str, Any]):
        context = dict(context)
        context["name"] = name
        context["updated"] = time.strftime("%Y-%m-%d %H:%M:%S")
        with self._path(name).open("w", encoding="utf-8") as f:
            json.dump(context, f, ensure_ascii=False, indent=2)

    def list(self) -> List[Dict[str, Any]]:
        items: List[Dict[str, Any]] = []
        for p in sorted(self.data_dir.glob("*.json")):
            try:
                with p.open("r", encoding="utf-8") as f:
                    d = json.load(f)
                    items.append({
                        "name": d.get("name", p.stem),
                        "type": d.get("type", ""),
                        "updated": d.get("updated", ""),
                    })
            except Exception:
                continue
        return items
