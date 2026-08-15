"""Ring 5 -- trust ledger.

    entry_n.hash = sha256(entry_{n-1}.hash + canonical_json(entry_n.payload))

Append-only. `verify()` re-walks the chain and names the first entry whose
recomputed hash disagrees with the stored one, so editing a row directly in
SQLite is provable rather than merely suspected.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from sqlalchemy import select

from ..db import LedgerRow, SessionLocal
from ..policy import Policy

GENESIS = "0" * 64


def canonical(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def digest(prev_hash: str, payload: dict[str, Any]) -> str:
    return hashlib.sha256((prev_hash + canonical(payload)).encode("utf-8")).hexdigest()


def args_digest(arguments: dict[str, Any]) -> str:
    return hashlib.sha256(canonical(arguments).encode("utf-8")).hexdigest()[:16]


def append(session_id: str, payload: dict[str, Any]) -> LedgerRow:
    with SessionLocal() as db:
        prev = db.execute(select(LedgerRow).order_by(LedgerRow.seq.desc()).limit(1)).scalar_one_or_none()
        prev_hash = prev.hash if prev else GENESIS
        row = LedgerRow(
            session_id=session_id,
            payload=payload,
            prev_hash=prev_hash,
            hash=digest(prev_hash, payload),
        )
        db.add(row)
        db.commit()
        db.refresh(row)
        return row


def verify() -> dict[str, Any]:
    """Re-walk the whole chain. Returns a report the dashboard renders directly."""
    with SessionLocal() as db:
        rows = db.execute(select(LedgerRow).order_by(LedgerRow.seq)).scalars().all()

    prev_hash = GENESIS
    for row in rows:
        if row.prev_hash != prev_hash:
            return {
                "valid": False, "entries": len(rows), "broken_at": row.seq,
                "session_id": row.session_id,
                "detail": (
                    f"entry #{row.seq} claims to follow {row.prev_hash[:12]}… but the "
                    f"previous entry hashes to {prev_hash[:12]}… — the chain was cut or "
                    f"an entry was removed."
                ),
            }
        recomputed = digest(row.prev_hash, row.payload)
        if recomputed != row.hash:
            return {
                "valid": False, "entries": len(rows), "broken_at": row.seq,
                "session_id": row.session_id,
                "detail": (
                    f"entry #{row.seq} ({row.payload.get('tool', '?')} / "
                    f"{row.payload.get('decision', '?')}) was altered: stored hash "
                    f"{row.hash[:12]}… but its contents hash to {recomputed[:12]}…"
                ),
            }
        prev_hash = row.hash

    return {
        "valid": True, "entries": len(rows), "broken_at": None,
        "head": prev_hash,
        "detail": f"all {len(rows)} entries verified against the genesis hash",
    }


# --- trust score --------------------------------------------------------

def apply_trust(policy: Policy, current: int, decision: str) -> int:
    """Decays fast on violations, recovers slowly on clean calls."""
    if decision == "BLOCK":
        nxt = current - policy.penalty("block_penalty", 22)
    elif decision == "ESCALATE":
        nxt = current - policy.penalty("escalate_penalty", 9)
    else:
        nxt = current + policy.penalty("clean_recovery", 2)
    return max(policy.penalty("floor", 0), min(policy.penalty("ceiling", 100), nxt))
