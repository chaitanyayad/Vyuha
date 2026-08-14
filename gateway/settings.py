"""Runtime configuration. Everything has a working default, so a fresh clone
runs with no .env file at all."""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent

load_dotenv(ROOT / ".env")


def _flag(name: str, default: bool) -> bool:
    return os.getenv(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


DB_URL = os.getenv("VYUHA_DB_URL", f"sqlite:///{(ROOT / 'vyuha.db').as_posix()}")
POLICY_PATH = Path(os.getenv("VYUHA_POLICY", ROOT / "policies" / "default.yaml"))
FIXTURE_PATH = Path(os.getenv("VYUHA_FIXTURE", ROOT / "sandbox" / "corp_data" / "fixture.json"))

# Enforcement is flipped at runtime through /api/toggle; this is only the
# boot value.
ENFORCE_DEFAULT = _flag("VYUHA_ENFORCE", True)

# Ring 4 is optional by design. Without a key it falls back to the local
# heuristic judge, so the system stays fully functional offline.
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
JUDGE_MODEL = os.getenv("VYUHA_JUDGE_MODEL", "claude-haiku-4-5-20251001")
JUDGE_BACKEND = os.getenv("VYUHA_JUDGE_BACKEND", "auto")  # auto | heuristic | llm | off
JUDGE_TIMEOUT_S = float(os.getenv("VYUHA_JUDGE_TIMEOUT", "2.0"))

# Agent planner: scripted is deterministic and offline, and is what the
# scenario suites run on; llm drives a real model if a key is present.
PLANNER = os.getenv("VYUHA_PLANNER", "scripted")  # scripted | llm
PLANNER_MODEL = os.getenv("VYUHA_PLANNER_MODEL", "claude-sonnet-5")

HOST = os.getenv("VYUHA_HOST", "127.0.0.1")
PORT = int(os.getenv("VYUHA_PORT", "8000"))
