from __future__ import annotations
from pathlib import Path
from typing import Dict, Any
import os

import yaml


def _read_yaml(p: Path) -> Dict[str, Any]:
    try:
        if p.exists():
            return yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    except Exception:
        pass
    return {}


def load_config(project_root: Path | None = None) -> Dict[str, Any]:
    """
    Load configuration with precedence (lowest to highest):
    - user config: ~/.htbcli/config.yaml
    - project config: <project>/.htbcli/config.yaml
    Environment variables are NOT merged here; shell will overlay envs on top.
    Returns a merged dict.
    """
    if project_root is None:
        project_root = Path.cwd()
    user_cfg = _read_yaml(Path.home() / ".htbcli" / "config.yaml")
    proj_cfg = _read_yaml(project_root / ".htbcli" / "config.yaml")

    merged: Dict[str, Any] = {}
    # simple deep-merge for two levels
    for src in (user_cfg, proj_cfg):
        for k, v in src.items():
            if isinstance(v, dict):
                merged.setdefault(k, {})
                merged[k].update(v)
            else:
                merged[k] = v
    return merged
