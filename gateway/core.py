"""The decision pipeline.

Rings run 1 -> 3 -> 2 -> 4 (Ring 3's tainted-egress rule needs Ring 1's
provenance; Ring 2 needs both), and the results are reported in ring order.
Ring 4 is skipped when Rings 1-3 have already hard-blocked -- it is the only
ring that can cost real milliseconds and it is never the reason a call dies.

Attribution rule: `caught_by` is the *lowest-numbered* ring that returned the
final decision, so "blocked at Ring 1" identifies the cheapest, most
deterministic layer that was sufficient on its own.
"""

from __future__ import annotations

import time
import uuid

from . import events
from .contract import SEVERITY, RingResult, ToolIntent, ToolResult, Verdict, worst
from .db import SessionLocal, SessionRow, ToolCallRow, init_db
from .policy import Policy, policy
from .rings import ring1_provenance, ring2_killchain, ring3_policy, ring4_judge, ring5_ledger
from .rings.base import RingContext
from .settings import ENFORCE_DEFAULT
from .store import STORE, CallNode, SessionStore


class Gateway:
    def __init__(self, store: SessionStore | None = None, pol: Policy | None = None,
                 enforced: bool | None = None, persist: bool = True) -> None:
        self.store = store or STORE
        self.policy = pol or policy()
        self.enforced = ENFORCE_DEFAULT if enforced is None else enforced
        self.persist = persist
        if persist:
            init_db()

    # --- sessions ------------------------------------------------------

    def open_session(self, goal: str, session_id: str | None = None, *,
                     kind: str = "benign", scenario: str = "") -> str:
        sid = session_id or f"s_{uuid.uuid4().hex[:10]}"
        start = self.policy.penalty("start", 100)
        self.store.open(sid, goal=goal, trust=start)
        self.store.get(sid).enforced = self.enforced
        if self.persist:
            with SessionLocal() as db:
                db.merge(SessionRow(id=sid, goal=goal, kind=kind, scenario=scenario,
                                    enforced=self.enforced, trust=start, started_at=time.time()))
                db.commit()
        # `kind` is the event envelope's own field -- name the session's
        # attack/benign classification differently or it silently overwrites it.
        events.publish("session_open", {"session_id": sid, "goal": goal,
                                        "session_kind": kind, "scenario": scenario,
                                        "enforced": self.enforced})
        return sid

    def close_session(self, session_id: str, outcome: str = "done") -> None:
        s = self.store.get(session_id)
        if self.persist:
            with SessionLocal() as db:
                row = db.get(SessionRow, session_id)
                if row:
                    row.ended_at, row.outcome, row.trust = time.time(), outcome, s.trust
                    db.commit()
        events.publish("session_close", {"session_id": session_id, "outcome": outcome,
                                         "trust": s.trust})

    def set_enforced(self, on: bool) -> bool:
        self.enforced = on
        events.publish("toggle", {"enforced": on})
        return self.enforced

    # --- the pipeline --------------------------------------------------

    def decide(self, intent: ToolIntent) -> Verdict:
        t0 = time.perf_counter()
        session = self.store.get(intent.session_id)
        node = CallNode(
            id=session.next_id("call"),
            index=len([n for n in session.nodes]) + 1,
            tool=intent.tool,
            arguments=dict(intent.arguments),
            justification=intent.justification,
        )
        ctx = RingContext(intent=intent, session=session, policy=self.policy, node=node)

        results: list[RingResult] = []
        r1 = ring1_provenance.run(ctx)
        results.append(r1)
        r3 = ring3_policy.run(ctx)
        results.append(r3)
        r2 = ring2_killchain.run(ctx)
        results.append(r2)

        hard_blocked = any(r.decision == "BLOCK" for r in results)
        if not hard_blocked:
            results.append(ring4_judge.run(ctx))

        results.sort(key=lambda r: r.ring)
        real = worst(*(r.decision for r in results)) if results else "ALLOW"
        caught_by = next(
            (r.ring for r in results if r.decision == real), None
        ) if real != "ALLOW" else None
        reason = next((r.reason for r in results if r.decision == real and r.ring == caught_by),
                      "permitted by all rings")

        enforced = self.enforced
        decision = real if enforced else "ALLOW"
        if not enforced and real != "ALLOW":
            reason = f"VYUHA disabled — pass-through. Rings would have returned {real}: {reason}"

        trust_before = session.trust
        session.trust = ring5_ledger.apply_trust(self.policy, trust_before, real)

        node.decision = decision
        node.caught_by = caught_by
        node.reason = reason
        session.nodes.append(node)
        if decision == "ALLOW":
            session.rates[intent.tool] += 1

        verdict = Verdict(
            intent_id=node.id, session_id=session.id, tool=intent.tool,
            decision=decision, ring_results=results, reason=reason,
            trust_after=session.trust, caught_by=caught_by, enforced=enforced,
            # Only set when the rings disagreed with what pass-through let
            # through — an ALLOW the gateway would also have allowed is not a
            # near miss and should not be drawn as one.
            shadow_decision=None if (enforced or real == "ALLOW") else real,
            elapsed_ms=(time.perf_counter() - t0) * 1000,
        )

        self._record(session.id, node, verdict, ctx)
        return verdict

    def observe(self, session_id: str, intent_id: str, result: ToolResult) -> ToolResult:
        """Called by the agent after it executes an allowed tool. This is how
        output provenance enters the graph."""
        session = self.store.get(session_id)
        if not result.id:
            result = result.model_copy(update={"id": session.next_id("out")})
        session.record_output(intent_id, result)
        node = session.node(intent_id)
        if node:
            node.origins.add(result.origin)
        if self.persist:
            with SessionLocal() as db:
                row = db.get(ToolCallRow, intent_id)
                if row:
                    row.executed = True
                    db.commit()
        events.publish("tool_output", {
            "session_id": session_id, "intent_id": intent_id, "output_id": result.id,
            "tool": result.tool, "origin": str(result.origin), "source": result.source,
            "preview": result.value[:240],
        })
        return result

    # --- ledger + persistence ------------------------------------------

    def _record(self, session_id: str, node: CallNode, verdict: Verdict, ctx: RingContext) -> None:
        payload = {
            "session_id": session_id,
            "intent_id": node.id,
            "index": node.index,
            "tool": node.tool,
            "args_digest": ring5_ledger.args_digest(node.arguments),
            "destination": node.destination,
            "decision": verdict.decision,
            "shadow_decision": verdict.shadow_decision,
            "caught_by": verdict.caught_by,
            "reason": verdict.reason,
            "rings": [{"ring": r.ring, "decision": r.decision, "score": r.score}
                      for r in verdict.ring_results],
            "trust_after": verdict.trust_after,
            "enforced": verdict.enforced,
        }
        entry = None
        if self.persist:
            entry = ring5_ledger.append(session_id, payload)
            with SessionLocal() as db:
                db.merge(ToolCallRow(
                    id=node.id, session_id=session_id, idx=node.index, tool=node.tool,
                    arguments=node.arguments, justification=node.justification,
                    derived_from=node.derived_from, decision=verdict.decision,
                    caught_by=verdict.caught_by, reason=verdict.reason,
                    ring_results=[r.model_dump() for r in verdict.ring_results],
                    trust_after=verdict.trust_after, enforced=verdict.enforced,
                    latency_ms=verdict.elapsed_ms, ts=time.time(),
                ))
                row = db.get(SessionRow, session_id)
                if row:
                    row.trust = verdict.trust_after
                db.commit()

        events.publish("decision", {
            "session_id": session_id,
            "verdict": verdict.model_dump(),
            "ledger_seq": entry.seq if entry else None,
            "ledger_hash": entry.hash if entry else None,
            "tainted_sources": ctx.tainted_sources,
        })


GATEWAY = Gateway()
