from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any


CONFIG_DIR = Path(__file__).with_name("config")


@lru_cache
def load_json_config(name: str) -> dict[str, Any]:
    path = CONFIG_DIR / name
    return json.loads(path.read_text(encoding="utf-8"))


def organization_config() -> dict[str, Any]:
    return load_json_config("organization.json")


def scoring_config() -> dict[str, Any]:
    return load_json_config("scoring.json")
