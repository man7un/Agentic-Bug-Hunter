#!/usr/bin/env python3
"""
confirm_common.py — shared proof-artifact contract for the confirm_*.py harnesses.

Each confirm_*.py tool (confirm_idor, confirm_authbypass, confirm_xss, confirm_ssrf)
independently re-tests a claimed finding and writes one of these artifacts instead
of asking a human/agent to self-report what they saw. validate.py reads the artifact
back via --proof and uses its verdict to auto-answer the exploitability gate,
rather than trusting a narrative claim.

Verdicts:
  CONFIRMED   — the harness independently reproduced real impact (mechanical check,
                not an LLM judgment call: a diff matched, a callback arrived, a
                payload executed in-browser, etc).
  POSSIBLE    — a signal was present but the harness couldn't prove impact
                (e.g. a payload reflected but never executed).
  UNCONFIRMED — the harness ran and found nothing.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone

CONFIRMED = "CONFIRMED"
POSSIBLE = "POSSIBLE"
UNCONFIRMED = "UNCONFIRMED"
VERDICTS = (CONFIRMED, POSSIBLE, UNCONFIRMED)


@dataclass
class Proof:
    tool: str            # which confirm_*.py produced this
    vuln_class: str      # idor | ssrf | auth_bypass | xss
    target_url: str
    verdict: str         # one of VERDICTS
    evidence: dict = field(default_factory=dict)
    timestamp: str = ""

    def __post_init__(self):
        if self.verdict not in VERDICTS:
            raise ValueError(f"verdict must be one of {VERDICTS}, got {self.verdict!r}")
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()


def write_proof(path: str, proof: Proof) -> str:
    """Write a Proof to `path` (creating parent dirs) and return the path."""
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    with open(path, "w") as f:
        json.dump(asdict(proof), f, indent=2)
    return path


def read_proof(path: str) -> Proof | None:
    """Read a Proof back from disk. Returns None if the file is missing or malformed
    — callers must treat that the same as "no automated confirmation available"."""
    try:
        with open(path) as f:
            data = json.load(f)
        return Proof(**data)
    except (FileNotFoundError, json.JSONDecodeError, TypeError, ValueError):
        return None
