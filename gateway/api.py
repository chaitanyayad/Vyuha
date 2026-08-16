"""The gateway HTTP surface and the dashboard host.

    uvicorn gateway.api:app --reload
"""

from __future__ import annotations

import asyncio
import json
import queue
import threading
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from sqlalchemy import select

from . import events
from .contract import ToolIntent, ToolResult, Verdict
from .core import GATEWAY
from .db import LedgerRow, SessionLocal, SessionRow, ToolCallRow, init_db, reset_db
from .policy import reload_policy
from .rings.ring5_ledger import verify
from .settings import ROOT

DASHBOARD = ROOT / "dashboard"

app = FastAPI(title="VYUHA", version="0.1.0",
              description="A layered trust gateway for tool-using AI agents.")

templates = Jinja2Templates(directory=str(DASHBOARD / "templates"))
if (DASHBOARD / "static").exists():
    app.mount("/static", StaticFiles(directory=str(DASHBOARD / "static")), name="static")

# The live sandbox the dashboard's scenario buttons drive. Test and benchmark
# runs each build their own, so nothing here affects the numbers.
from sandbox.env import CorpEnv  # noqa: E402

LIVE_ENV = CorpEnv()
_run_lock = threading.Lock()


@app.on_event("startup")
def _startup() -> None:
    init_db()


# --- gateway API --------------------------------------------------------

class OpenSession(BaseModel):
    goal: str
    session_id: str | None = None
    kind: str = "benign"
    scenario: str = ""


class Observation(BaseModel):
    session_id: str
    intent_id: str
    result: ToolResult


@app.get("/health")
def health() -> dict[str, Any]:
    return {"status": "ok", "enforced": GATEWAY.enforced}


@app.post("/api/session")
def open_session(body: OpenSession) -> dict[str, str]:
    return {"session_id": GATEWAY.open_session(body.goal, body.session_id,
                                               kind=body.kind, scenario=body.scenario)}


@app.post("/api/decide", response_model=Verdict)
def decide(intent: ToolIntent) -> Verdict:
    return GATEWAY.decide(intent)


@app.post("/api/observe")
def observe(body: Observation) -> dict[str, str]:
    result = GATEWAY.observe(body.session_id, body.intent_id, body.result)
    return {"output_id": result.id}


@app.post("/api/toggle")
def toggle(on: bool | None = None) -> dict[str, bool]:
    """Enable or disable enforcement without restarting: same agent, same
    scenario, opposite outcome."""
    return {"enforced": GATEWAY.set_enforced(not GATEWAY.enforced if on is None else on)}


@app.get("/api/state")
def state() -> dict[str, Any]:
    report = verify()
    return {
        "enforced": GATEWAY.enforced,
        "sessions": len(GATEWAY.store.all()),
        "ledger": {"entries": report["entries"], "valid": report["valid"]},
    }


@app.get("/api/ledger/verify")
def ledger_verify() -> dict[str, Any]:
    """Re-walk the hash chain. Edit a row in SQLite and this reports which
    entry no longer matches its stored hash."""
    return verify()


@app.get("/api/ledger")
def ledger(limit: int = 50) -> list[dict[str, Any]]:
    with SessionLocal() as db:
        rows = db.execute(
            select(LedgerRow).order_by(LedgerRow.seq.desc()).limit(limit)
        ).scalars().all()
    return [{"seq": r.seq, "ts": r.ts, "session_id": r.session_id,
             "hash": r.hash, "prev_hash": r.prev_hash, "payload": r.payload}
            for r in rows]


@app.get("/api/sessions")
def sessions(limit: int = 40) -> list[dict[str, Any]]:
    with SessionLocal() as db:
        rows = db.execute(
            select(SessionRow).order_by(SessionRow.started_at.desc()).limit(limit)
        ).scalars().all()
        out = []
        for s in rows:
            calls = db.execute(
                select(ToolCallRow).where(ToolCallRow.session_id == s.id)
            ).scalars().all()
            out.append({
                "id": s.id, "goal": s.goal, "kind": s.kind, "scenario": s.scenario,
                "enforced": s.enforced, "trust": s.trust, "outcome": s.outcome,
                "started_at": s.started_at, "steps": len(calls),
                "blocked": sum(1 for c in calls if c.decision == "BLOCK"),
            })
        return out


@app.get("/api/sessions/{session_id}")
def session_detail(session_id: str) -> dict[str, Any]:
    with SessionLocal() as db:
        row = db.get(SessionRow, session_id)
        if row is None:
            raise HTTPException(404, f"no session {session_id}")
        calls = db.execute(
            select(ToolCallRow).where(ToolCallRow.session_id == session_id)
            .order_by(ToolCallRow.idx)
        ).scalars().all()
    return {
        "session": {"id": row.id, "goal": row.goal, "kind": row.kind,
                    "scenario": row.scenario, "enforced": row.enforced,
                    "trust": row.trust, "outcome": row.outcome},
        "calls": [{"id": c.id, "idx": c.idx, "tool": c.tool, "arguments": c.arguments,
                   "justification": c.justification, "derived_from": c.derived_from,
                   "decision": c.decision, "caught_by": c.caught_by, "reason": c.reason,
                   "ring_results": c.ring_results, "trust_after": c.trust_after,
                   "executed": c.executed, "latency_ms": c.latency_ms} for c in calls],
    }


@app.get("/api/outbox")
def outbox() -> list[dict[str, Any]]:
    """The outbound log: what a run actually sent, so a leak is observable
    rather than asserted."""
    leaked = {id(d) for d in LIVE_ENV.leaked_externally()}
    return [{"channel": d.channel, "destination": d.destination, "subject": d.subject,
             "body": d.body[:600], "ts": d.ts, "session_id": d.session_id,
             "external": id(d) in leaked}
            for d in reversed(LIVE_ENV.deliveries())]


@app.get("/api/results")
def results() -> dict[str, Any]:
    """The benchmark output, so the dashboard and any write-up read the same
    numbers from the same file."""
    path = ROOT / "results.json"
    if not path.exists():
        raise HTTPException(404, "results.json not found — run `make benchmark` first")
    return json.loads(path.read_text(encoding="utf-8"))


@app.get("/api/scenarios")
def scenarios() -> list[dict[str, Any]]:
    from redteam.scenarios import ALL
    return [{"id": s.id, "name": s.name, "category": s.category, "goal": s.goal,
             "kind": "attack" if s.id.startswith("A") else "benign",
             "steps": len(s.steps), "expect_ring": s.expect_ring, "notes": s.notes}
            for s in ALL]


@app.post("/api/run/{scenario_id}")
def run_scenario_live(scenario_id: str) -> dict[str, Any]:
    """Run a scenario through the *live* gateway, so the dashboard observes the
    decisions as they happen and the enforcement toggle governs the run."""
    from redteam.runner import run_scenario
    from redteam.scenarios import by_id

    try:
        scenario = by_id(scenario_id)
    except KeyError:
        raise HTTPException(404, f"no scenario {scenario_id}")

    if not _run_lock.acquire(blocking=False):
        raise HTTPException(409, "a scenario is already running")
    try:
        outcome = run_scenario(scenario, gateway=GATEWAY, env=LIVE_ENV)
    finally:
        _run_lock.release()

    return {
        "scenario": scenario.id,
        "session_id": outcome.report.session_id,
        "enforced": GATEWAY.enforced,
        "leaked": [d.summary() for d in outcome.leaked],
        "attack_succeeded": outcome.attack_succeeded,
        "caught_by": outcome.rings_that_caught,
        "steps": len(outcome.report.traces),
    }


@app.post("/api/reset")
def reset(wipe_ledger: bool = False) -> dict[str, Any]:
    """Reseed the sandbox and clear session state, so consecutive runs start
    from identical conditions."""
    LIVE_ENV.reset()
    GATEWAY.store.clear()
    reload_policy()
    if wipe_ledger:
        reset_db()
    return {"reset": True, "ledger_wiped": wipe_ledger}


# --- live event stream --------------------------------------------------

@app.get("/api/events")
async def event_stream(request: Request) -> StreamingResponse:
    q = events.subscribe()

    async def generate():
        try:
            for event in events.recent(30):
                yield f"data: {json.dumps(event, default=str)}\n\n"
            while True:
                if await request.is_disconnected():
                    break
                try:
                    event = q.get_nowait()
                    yield f"data: {json.dumps(event, default=str)}\n\n"
                except queue.Empty:
                    await asyncio.sleep(0.15)
                    yield ": keepalive\n\n"
        finally:
            events.unsubscribe(q)

    return StreamingResponse(generate(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache",
                                      "X-Accel-Buffering": "no"})


# --- dashboard ----------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(request, "dashboard.html",
                                      {"enforced": GATEWAY.enforced})
