"""Ring 5: tampering with the database must be provable.

Editing a row directly in SQLite has to break verification and identify the
entry that changed. If these fail, the ledger is a log rather than evidence.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select, update

from gateway.db import LedgerRow, SessionLocal, init_db, reset_db
from gateway.policy import load_policy
from gateway.rings.ring5_ledger import apply_trust, verify
from redteam.runner import run_scenario
from redteam.scenarios import by_id


@pytest.fixture
def seeded_ledger():
    reset_db()
    run_scenario(by_id("A04"), enforced=True, persist=True)
    yield
    reset_db()


def test_clean_chain_verifies(seeded_ledger):
    report = verify()
    assert report["valid"], report
    assert report["entries"] > 0


def test_edited_row_breaks_the_chain_and_is_named(seeded_ledger):
    with SessionLocal() as db:
        target = db.execute(select(LedgerRow).order_by(LedgerRow.seq)).scalars().all()[1]
        seq, payload = target.seq, dict(target.payload)
        payload["decision"] = "ALLOW"          # rewrite history
        payload["reason"] = "looked fine to me"
        db.execute(update(LedgerRow).where(LedgerRow.seq == seq).values(payload=payload))
        db.commit()

    report = verify()
    assert not report["valid"]
    assert report["broken_at"] == seq
    assert str(seq) in report["detail"]


def test_deleted_entry_breaks_the_chain(seeded_ledger):
    with SessionLocal() as db:
        rows = db.execute(select(LedgerRow).order_by(LedgerRow.seq)).scalars().all()
        db.delete(rows[1])
        db.commit()

    report = verify()
    assert not report["valid"]


def test_trust_decays_fast_and_recovers_slowly():
    policy = load_policy()
    trust = 100
    trust = apply_trust(policy, trust, "BLOCK")
    assert trust < 100
    dropped = trust
    for _ in range(3):
        trust = apply_trust(policy, trust, "ALLOW")
    assert trust > dropped
    assert trust < 100, "three clean calls should not undo a violation"
    assert apply_trust(policy, 0, "BLOCK") == 0, "score must not go negative"
