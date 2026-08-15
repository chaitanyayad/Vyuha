"""Ring 3 -- capability policy.

Deterministic, microseconds, no cleverness. Everything here is provable from
policies/default.yaml, which is what makes it the ring an auditor can check
without reading any code.
"""

from __future__ import annotations

import re

from ..contract import RingResult
from .base import RingContext, timed

RING = 3
NAME = "capability-policy"


def run(ctx: RingContext) -> RingResult:
    with timed() as t:
        result = _evaluate(ctx)
    result.elapsed_ms = t.ms
    return result


def _evaluate(ctx: RingContext) -> RingResult:
    intent, pol = ctx.intent, ctx.policy
    tp = pol.for_tool(intent.tool)

    if tp is None:
        return _block(f"'{intent.tool}' is not a declared capability; default deny", 100,
                      rule="unknown_tool")

    # --- trust floor ---------------------------------------------------
    if ctx.session.trust < tp.requires_trust:
        return _block(
            f"'{intent.tool}' requires trust {tp.requires_trust}; session trust is "
            f"{ctx.session.trust} after earlier violations",
            80, rule="requires_trust",
            required=tp.requires_trust, actual=ctx.session.trust,
        )

    # --- rate limit ----------------------------------------------------
    if tp.rate_limit is not None:
        used = ctx.session.rates[intent.tool]
        if used >= tp.rate_limit:
            return _block(
                f"rate limit for '{intent.tool}' exhausted ({used}/{tp.rate_limit} this session)",
                70, rule="rate_limit", used=used, limit=tp.rate_limit,
            )

    # --- tool-wide deny patterns --------------------------------------
    blob = ctx.arg_text()
    for pattern in tp.deny_patterns:
        if re.search(pattern, blob):
            return _block(
                f"argument matched denied pattern /{pattern}/ for '{intent.tool}'",
                90, rule="deny_pattern", pattern=pattern,
            )

    # --- per-argument rules -------------------------------------------
    for rule in tp.argument_rules:
        value = intent.arguments.get(rule.field)
        if value is None:
            continue
        value = str(value)

        if not rule.domains_ok(value):
            return _block(
                f"'{rule.field}={value}' is outside the allowed domains "
                f"{rule.must_match_domain}",
                85, rule="must_match_domain", field=rule.field, value=value,
            )

        if not rule.host_ok(value):
            return _block(
                f"'{rule.field}={value}' is outside the allowed hosts {rule.must_match_host}",
                85, rule="must_match_host", field=rule.field, value=value,
            )

        for pattern in rule.deny_patterns:
            if re.search(pattern, value):
                return _block(
                    f"'{rule.field}' matched denied pattern /{pattern}/",
                    85, rule="deny_pattern", field=rule.field, pattern=pattern,
                )

        if rule.max_len is not None and len(value) > rule.max_len:
            return _block(
                f"'{rule.field}' is {len(value)} chars, over the {rule.max_len} limit",
                50, rule="max_len", field=rule.field,
            )

        if rule.deny_tainted_egress and rule.field in ctx.tainted_fields and ctx.destination_external:
            srcs = ", ".join(ctx.tainted_sources)
            return _block(
                f"'{rule.field}' carries untrusted content ({srcs}) and this call leaves "
                f"the trust boundary for '{ctx.destination}'",
                88, rule="deny_tainted_egress", field=rule.field,
            )

    return RingResult(
        ring=RING, name=NAME, decision="ALLOW", score=0,
        reason=f"'{intent.tool}' permitted by policy (scopes {tp.scopes or ['-']})",
        evidence={"scopes": tp.scopes, "rate_used": ctx.session.rates[intent.tool],
                  "rate_limit": tp.rate_limit},
    )


def _block(reason: str, score: int, **evidence) -> RingResult:
    return RingResult(ring=RING, name=NAME, decision="BLOCK", score=score,
                      reason=reason, evidence=evidence)
