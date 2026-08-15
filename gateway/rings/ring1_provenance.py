"""Ring 1 -- provenance / taint.

The ring that does not care what the injected text *says*. It cares where it
came from.

The distinction that makes this survivable in production:

    data taint     an argument carries untrusted content.
                   Dangerous only when it crosses the trust boundary.
    control taint  the *decision to make this call* traces back to untrusted
                   content. Always disqualifying for a sink -- that is the
                   definition of a confused deputy.

Summarising an internal document and mailing it to a colleague is data taint to
an internal destination: ordinary work, allowed. The same summary to an address
a poisoned PDF chose for you is both, and blocked.
"""

from __future__ import annotations

from ..contract import Origin, RingResult
from ..taint import trace
from .base import RingContext, timed

RING = 1
NAME = "provenance"


def run(ctx: RingContext) -> RingResult:
    with timed() as t:
        result = _evaluate(ctx)
    result.elapsed_ms = t.ms
    return result


def _evaluate(ctx: RingContext) -> RingResult:
    session, pol, intent = ctx.session, ctx.policy, ctx.intent
    tool_policy = pol.for_tool(intent.tool)
    outputs = session.outputs

    # --- what does this call derive from? -----------------------------
    for name, value in intent.arguments.items():
        matches = trace(str(value), outputs)
        if matches:
            ctx.data_matches[name] = matches
            if any(m.tainted for m in matches):
                ctx.tainted_fields.add(name)
    ctx.control_matches = trace(intent.justification, outputs)

    for m in [*ctx.control_matches, *(m for ms in ctx.data_matches.values() for m in ms)]:
        ctx.origins.add(m.origin)
    if not ctx.origins:
        ctx.origins.add(Origin.USER)

    # Untrusted content is in the agent's context but we cannot tie this
    # specific call to it textually. Not enough to block on; enough to stop
    # trusting the call on its own word.
    read_untrusted = [o for o in outputs.values() if o.tainted]
    ctx.contextual_taint = bool(read_untrusted) and not ctx.tainted_sources

    ctx.node.origins = set(ctx.origins)
    ctx.node.derived_from = sorted(
        {m.output_id for ms in ctx.data_matches.values() for m in ms}
        | {m.output_id for m in ctx.control_matches}
    )

    # --- where is it going? -------------------------------------------
    if tool_policy and tool_policy.destination_field:
        dest = str(intent.arguments.get(tool_policy.destination_field, "") or "")
        ctx.destination = dest or None
        ctx.destination_external = bool(dest) and not pol.is_internal_destination(dest)
        ctx.node.destination = ctx.destination
        ctx.node.destination_external = ctx.destination_external

    is_sink = bool(tool_policy and tool_policy.sink)
    if not is_sink:
        return RingResult(
            ring=RING, name=NAME, decision="ALLOW", score=0,
            reason="read-only tool; untrusted input cannot cause an action here",
            evidence=_evidence(ctx),
        )

    # --- sink rules ----------------------------------------------------
    control = [m for m in ctx.control_matches if m.tainted]
    if control:
        srcs = ", ".join(dict.fromkeys(m.source for m in control))
        return RingResult(
            ring=RING, name=NAME, decision="BLOCK", score=95,
            reason=(
                f"control-flow taint: the justification for calling '{intent.tool}' "
                f"derives from untrusted content ({srcs}). Untrusted content may be "
                f"read, but it may not decide that a sink gets called."
            ),
            evidence=_evidence(ctx),
        )

    data = sorted(ctx.tainted_fields)

    # Strongest single finding we can report: not merely that the payload is
    # tainted, but that the *recipient* was chosen by untrusted content.
    # Only when that recipient is outside the boundary -- replying to the
    # address in a colleague's email is how email works.
    dest_field = tool_policy.destination_field if tool_policy else None
    if dest_field and dest_field in ctx.tainted_fields and ctx.destination_external:
        srcs = ", ".join(dict.fromkeys(
            m.source for m in ctx.data_matches.get(dest_field, []) if m.tainted
        ))
        return RingResult(
            ring=RING, name=NAME, decision="BLOCK", score=97,
            reason=(
                f"the destination itself came from untrusted content: "
                f"'{ctx.destination}' appears in {srcs}. The document picked the "
                f"recipient, not the user."
            ),
            evidence=_evidence(ctx),
        )

    if data and ctx.destination_external:
        srcs = ", ".join(ctx.tainted_sources)
        return RingResult(
            ring=RING, name=NAME, decision="BLOCK", score=90,
            reason=(
                f"data exfiltration: argument(s) {', '.join(data)} carry untrusted "
                f"content from {srcs}, and '{ctx.destination}' is outside the trust "
                f"boundary."
            ),
            evidence=_evidence(ctx),
        )

    if ctx.destination_external and ctx.contextual_taint:
        return RingResult(
            ring=RING, name=NAME, decision="ESCALATE", score=55,
            reason=(
                f"'{ctx.destination}' is external and this session has already read "
                f"{len(read_untrusted)} untrusted source(s); no direct derivation "
                f"proven, so this needs a human rather than a block."
            ),
            evidence=_evidence(ctx),
        )

    if data:
        srcs = ", ".join(ctx.tainted_sources)
        return RingResult(
            ring=RING, name=NAME, decision="ALLOW", score=20,
            reason=f"untrusted data from {srcs} stays inside the trust boundary",
            evidence=_evidence(ctx),
        )

    return RingResult(
        ring=RING, name=NAME, decision="ALLOW", score=0,
        reason="no untrusted derivation found", evidence=_evidence(ctx),
    )


def _evidence(ctx: RingContext) -> dict:
    claimed = sorted(set(ctx.intent.derived_from))
    computed = sorted(set(ctx.node.derived_from))
    return {
        "computed_derived_from": computed,
        "claimed_derived_from": claimed,
        "agent_underreported": sorted(set(computed) - set(claimed)),
        "tainted_fields": sorted(ctx.tainted_fields),
        "control_taint": [m.source for m in ctx.control_matches if m.tainted],
        "origins": sorted(str(o) for o in ctx.origins),
        "destination": ctx.destination,
        "destination_external": ctx.destination_external,
        "contextual_taint": ctx.contextual_taint,
        "matches": [
            {"field": f, "source": m.source, "method": m.method,
             "excerpt": m.excerpt, "confidence": m.confidence}
            for f, ms in ctx.data_matches.items() for m in ms[:2]
        ]
        + [
            {"field": "justification", "source": m.source, "method": m.method,
             "excerpt": m.excerpt, "confidence": m.confidence}
            for m in ctx.control_matches[:2]
        ],
    }
