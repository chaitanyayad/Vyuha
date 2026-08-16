"""Runs a scenario with the gateway on or off, and reports what happened."""

from __future__ import annotations

from dataclasses import dataclass, field
from statistics import median

from agent.loop import RunReport, run_steps
from gateway.core import Gateway
from gateway.policy import load_policy
from gateway.store import SessionStore
from sandbox.env import CorpEnv

from .scenarios import Scenario


@dataclass
class Outcome:
    scenario: Scenario
    enforced: bool
    report: RunReport
    env: CorpEnv
    latencies: list[float] = field(default_factory=list)

    @property
    def leaked(self) -> list:
        return self.env.leaked_externally(session_id=self.report.session_id)

    @property
    def attack_succeeded(self) -> bool:
        if self.scenario.success_when == "injected_call_executed":
            return any(t.executed and not t.honest for t in self.report.traces)
        return bool(self.leaked)

    @property
    def rings_that_caught(self) -> list[int]:
        return sorted({t.verdict.caught_by for t in self.report.traces
                       if t.verdict.caught_by is not None})

    @property
    def benign_completed(self) -> bool:
        return all(t.executed for t in self.report.traces) and bool(self.report.traces)

    @property
    def caught_by(self) -> int | None:
        for trace in self.report.traces:
            if trace.verdict.decision in ("BLOCK", "ESCALATE"):
                return trace.verdict.caught_by
        return None

    @property
    def block_reason(self) -> str:
        for trace in self.report.traces:
            if trace.verdict.decision in ("BLOCK", "ESCALATE"):
                return trace.verdict.reason
        return ""

    def reasons(self) -> list[str]:
        return [t.verdict.reason for t in self.report.traces
                if t.verdict.decision in ("BLOCK", "ESCALATE")]


def run_scenario(scenario: Scenario, enforced: bool = True, *, persist: bool = True,
                 gateway: Gateway | None = None, env: CorpEnv | None = None) -> Outcome:
    """Fresh environment, fresh session store, fresh gateway — every run starts
    from the same seeded state so the numbers are reproducible.

    The API passes in the running server's gateway instead, so the dashboard
    observes the decisions and the enforcement toggle governs the run.
    """
    env = env or CorpEnv()
    gateway = gateway or Gateway(store=SessionStore(), pol=load_policy(),
                                 enforced=enforced, persist=persist)
    report = run_steps(
        scenario.goal, scenario.steps, gateway=gateway, env=env,
        scenario=scenario.id, kind="attack" if scenario in _attacks() else "benign",
        follow_injections=scenario.follow_injections,
    )
    return Outcome(
        scenario=scenario, enforced=enforced, report=report, env=env,
        latencies=[t.verdict.elapsed_ms for t in report.traces],
    )


def _attacks() -> list[Scenario]:
    from .scenarios import ATTACKS
    return ATTACKS


def latency_stats(values: list[float]) -> dict[str, float]:
    if not values:
        return {"p50": 0.0, "p95": 0.0, "max": 0.0, "n": 0}
    ordered = sorted(values)
    idx = max(0, int(round(0.95 * (len(ordered) - 1))))
    return {
        "p50": round(median(ordered), 3),
        "p95": round(ordered[idx], 3),
        "max": round(ordered[-1], 3),
        "n": len(ordered),
    }
