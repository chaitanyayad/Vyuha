"""The agent loop.

plan -> propose intent -> submit to gateway -> receive verdict -> execute or
re-plan. The agent cannot call a tool directly; `tools.execute` is only ever
reached after an ALLOW.

A session opens with a declared goal because Ring 2 needs something to measure
drift against.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from gateway.contract import ToolIntent, ToolResult, Verdict
from gateway.core import GATEWAY, Gateway
from sandbox.env import ENV, CorpEnv

from . import tools
from .planner import Planner, ScriptedPlanner, Step

MAX_STEPS = 16


@dataclass
class Trace:
    step: int
    tool: str
    arguments: dict[str, Any]
    justification: str
    verdict: Verdict
    executed: bool
    result_preview: str = ""
    injected_from: str = ""
    # False when this step came from injected content rather than the goal.
    # Ground truth for scoring; the gateway never sees it.
    honest: bool = True


@dataclass
class RunReport:
    session_id: str
    goal: str
    scenario: str = ""
    traces: list[Trace] = field(default_factory=list)
    pending: list[Trace] = field(default_factory=list)
    completed: bool = False

    @property
    def blocked(self) -> list[Trace]:
        return [t for t in self.traces if t.verdict.decision == "BLOCK"]

    @property
    def escalated(self) -> list[Trace]:
        return [t for t in self.traces if t.verdict.decision == "ESCALATE"]

    @property
    def executed(self) -> list[Trace]:
        return [t for t in self.traces if t.executed]

    def deliveries(self, env: CorpEnv = ENV):
        return env.deliveries(self.session_id)

    def leaked(self, env: CorpEnv = ENV):
        return env.leaked_externally(session_id=self.session_id)

    @property
    def trust(self) -> int:
        return self.traces[-1].verdict.trust_after if self.traces else 100


class Agent:
    def __init__(self, gateway: Gateway | None = None, env: CorpEnv = ENV) -> None:
        self.gateway = gateway or GATEWAY
        self.env = env

    def run(self, goal: str, planner: Planner, *, scenario: str = "",
            kind: str = "benign", max_steps: int = MAX_STEPS) -> RunReport:
        session_id = self.gateway.open_session(goal, kind=kind, scenario=scenario)
        report = RunReport(session_id=session_id, goal=goal, scenario=scenario)
        last_output_id = ""

        step = planner.next()  # type: ignore[attr-defined]
        n = 0
        while step is not None and n < max_steps:
            n += 1
            intent = ToolIntent(
                session_id=session_id,
                tool=step.tool,
                arguments=step.arguments,
                justification=step.justification,
                # The agent's own claim. Injected steps do not report their
                # provenance -- and the gateway computes it anyway.
                derived_from=[last_output_id] if (step.honest and last_output_id) else [],
            )
            verdict = self.gateway.decide(intent)

            trace = Trace(step=n, tool=step.tool, arguments=step.arguments,
                          justification=step.justification, verdict=verdict,
                          executed=False, injected_from=step.injected_from,
                          honest=step.honest)

            if verdict.decision == "ALLOW":
                result = tools.execute(step.tool, step.arguments, env=self.env,
                                       session_id=session_id)
                result = self.gateway.observe(session_id, verdict.intent_id, result)
                last_output_id = result.id
                trace.executed = True
                trace.result_preview = result.value[:200]
                report.traces.append(trace)
                planner.observe(step, result)
                step = planner.next()  # type: ignore[attr-defined]
                continue

            report.traces.append(trace)
            if verdict.decision == "ESCALATE":
                # Not executed. Parks in the pending queue for a human.
                report.pending.append(trace)

            retry = planner.on_block(step, verdict.reason)
            step = retry if retry is not None else planner.next()  # type: ignore[attr-defined]

        report.completed = step is None
        self.gateway.close_session(session_id,
                                   outcome="blocked" if report.blocked else "done")
        return report


def run_steps(goal: str, steps: list[Step], *, gateway: Gateway | None = None,
              env: CorpEnv = ENV, scenario: str = "", kind: str = "benign",
              follow_injections: bool = True) -> RunReport:
    """Convenience entry point used by the red-team and benign suites."""
    planner = ScriptedPlanner(steps, env=env, follow_injections=follow_injections)
    return Agent(gateway=gateway, env=env).run(
        goal, planner, scenario=scenario, kind=kind
    )
