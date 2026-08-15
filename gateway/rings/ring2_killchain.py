"""Ring 2 -- kill-chain correlation.

Ring 1 judges a call. Ring 2 judges the *sequence*. This is where it differs
from a request filter: a filter sees one request, while this keeps the causal
graph of the session and can block a chain in which no individual step looks
wrong.

Nodes are tool calls; an edge means this call's arguments or justification
derive from that earlier call's output (computed in Ring 1, walked
transitively through `Session.ancestors` so a laundering hop does not break
the link).
"""

from __future__ import annotations

from dataclasses import dataclass

from ..contract import RingResult
from ..taint import terms
from .base import RingContext, timed

RING = 2
NAME = "kill-chain"

BLOCK_AT = 70
ESCALATE_AT = 40

GOAL_DRIFT_FLOOR = 0.15   # share of goal terms the intent must still touch
MIN_GOAL_TERMS = 4        # below this a goal is too thin to measure drift against
MAX_SINK_CALLS = 4        # across all sink tools, per session


@dataclass
class Signal:
    name: str
    score: int
    reason: str
    steps: list[str]


def run(ctx: RingContext) -> RingResult:
    with timed() as t:
        signals = _detect(ctx)
    signals.sort(key=lambda s: -s.score)

    if not signals:
        return RingResult(
            ring=RING, name=NAME, decision="ALLOW", score=0,
            reason="no known chain pattern in this session's causal graph",
            evidence={"graph_size": len(ctx.session.nodes)}, elapsed_ms=t.ms,
        )

    top = signals[0]
    decision = "BLOCK" if top.score >= BLOCK_AT else (
        "ESCALATE" if top.score >= ESCALATE_AT else "ALLOW"
    )
    return RingResult(
        ring=RING, name=NAME, decision=decision, score=top.score,
        reason=top.reason,
        evidence={
            "chain": top.name,
            "steps": top.steps,
            "graph_size": len(ctx.session.nodes),
            "all_signals": [{"chain": s.name, "score": s.score} for s in signals],
        },
        elapsed_ms=t.ms,
    )


def _detect(ctx: RingContext) -> list[Signal]:
    out: list[Signal] = []
    for check in (_exfiltration, _probing, _confused_deputy, _goal_drift, _sink_burst):
        sig = check(ctx)
        if sig:
            out.append(sig)
    return out


def _label(node) -> str:
    dest = f" -> {node.destination}" if node.destination else ""
    return f"#{node.index} {node.tool}{dest}"


def _exfiltration(ctx: RingContext) -> Signal | None:
    """untrusted read ... -> sink call leaving the trust boundary."""
    if not ctx.policy.is_sink(ctx.intent.tool):
        return None

    chain = ctx.session.ancestors(ctx.node)
    untrusted_reads = [n for n in chain if n.tainted]

    if not untrusted_reads and ctx.contextual_taint:
        # No proven edge, but the session did read untrusted content before
        # reaching for an external sink. That is the slow-burn shape.
        untrusted_reads = [
            n for n in ctx.session.nodes
            if n.tainted and n.index < ctx.node.index and n.decision == "ALLOW"
        ]
        if not (untrusted_reads and ctx.destination_external):
            return None
        # Report the whole session path, not just the tainted reads: the point
        # of this signal is that no individual step looked wrong.
        path = [n for n in ctx.session.nodes
                if n.index < ctx.node.index and n.decision == "ALLOW"]
        steps = [_label(n) for n in [*path, ctx.node]]
        return Signal(
            "exfiltration", 78,
            (
                f"exfiltration chain over {len(steps)} steps "
                f"({' -> '.join(s.split(' ', 1)[1] for s in steps)}): untrusted content "
                f"entered at step #{untrusted_reads[0].index} ({untrusted_reads[0].tool}) "
                f"and this session is now calling '{ctx.intent.tool}' out to "
                f"'{ctx.destination}'. No single step was suspicious on its own."
            ),
            steps,
        )

    if not (untrusted_reads and ctx.destination_external):
        return None

    steps = [_label(n) for n in [*chain, ctx.node]]
    return Signal(
        "exfiltration", 92,
        (
            f"exfiltration chain over {len(steps)} steps: data from "
            f"{untrusted_reads[0].tool} (#{untrusted_reads[0].index}) reaches "
            f"'{ctx.destination}' outside the trust boundary via "
            f"{' -> '.join(s.split(' ', 1)[1] for s in steps)}."
        ),
        steps,
    )


def _probing(ctx: RingContext) -> Signal | None:
    """Repeated denials on the same tool with mutated arguments."""
    denied = [n for n in ctx.session.denials(ctx.intent.tool)]
    if len(denied) < 2:
        return None
    variants = {str(sorted(n.arguments.items())) for n in denied}
    variants.add(str(sorted(ctx.intent.arguments.items())))
    if len(variants) < 3:
        return None
    score = min(95, 55 + 15 * len(denied))
    return Signal(
        "probing", score,
        (
            f"argument probing: '{ctx.intent.tool}' has been denied {len(denied)} time(s) "
            f"in this session and the arguments were mutated each time "
            f"({len(variants)} distinct variants). This is search for a gap, not a retry."
        ),
        [_label(n) for n in [*denied, ctx.node]],
    )


def _confused_deputy(ctx: RingContext) -> Signal | None:
    """A granted credential used for a purpose that originated in untrusted text."""
    if ctx.policy.is_sink(ctx.intent.tool):
        return None  # Ring 1 owns the sink case
    tp = ctx.policy.for_tool(ctx.intent.tool)
    if not tp or not tp.privileged:
        return None
    control = [m for m in ctx.control_matches if m.tainted]
    if not control:
        return None
    srcs = ", ".join(dict.fromkeys(m.source for m in control))
    return Signal(
        "confused-deputy", 62,
        (
            f"confused deputy: '{ctx.intent.tool}' holds scope "
            f"{tp.scopes} legitimately, but the reason for using it here traces "
            f"to untrusted content ({srcs}). The credential is real; the instruction "
            f"is not the principal's."
        ),
        [_label(ctx.node)],
    )


def _goal_drift(ctx: RingContext) -> Signal | None:
    """Is this call still about what the session was opened to do?"""
    goal = ctx.session.goal
    if not goal or not ctx.policy.is_sink(ctx.intent.tool):
        return None
    goal_terms = terms(goal)
    # A two-word goal has nothing to drift from; measuring against it produces
    # noise, not signal. Say so rather than guessing.
    if len(goal_terms) < MIN_GOAL_TERMS:
        return None
    intent_terms = terms(f"{ctx.intent.tool} {ctx.arg_text()} {ctx.intent.justification}")
    overlap = len(goal_terms & intent_terms) / len(goal_terms)
    if overlap >= GOAL_DRIFT_FLOOR:
        return None
    score = 68 if ctx.destination_external else 45
    return Signal(
        "goal-drift", score,
        (
            f"goal drift: session goal was \"{goal[:70]}\" but this "
            f"'{ctx.intent.tool}' call shares {overlap:.0%} of the goal's terms"
            + (f" and targets external '{ctx.destination}'" if ctx.destination_external else "")
            + "."
        ),
        [_label(ctx.node)],
    )


def _sink_burst(ctx: RingContext) -> Signal | None:
    """Rate-limit evasion by alternating between sink tools."""
    if not ctx.policy.is_sink(ctx.intent.tool):
        return None
    sinks = [n for n in ctx.session.nodes if ctx.policy.is_sink(n.tool) and n.decision == "ALLOW"]
    if len(sinks) < MAX_SINK_CALLS:
        return None
    return Signal(
        "sink-burst", 66,
        (
            f"sink burst: {len(sinks)} outbound calls already succeeded in this session "
            f"across {len({n.tool for n in sinks})} different sink tools. Per-tool rate "
            f"limits are being spread rather than exceeded."
        ),
        [_label(n) for n in [*sinks, ctx.node]],
    )
