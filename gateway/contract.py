"""The interface between the agent and the gateway.

Both sides import from here, so this module is the whole contract. Changing a
field here changes the boundary the rest of the system is built on.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field


class Origin(StrEnum):
    """Where a span of text entered the agent's context."""

    USER = "USER"
    SYSTEM = "SYSTEM"
    TOOL_OUTPUT = "TOOL_OUTPUT"
    RETRIEVED_DOC = "RETRIEVED_DOC"
    EXTERNAL_MSG = "EXTERNAL_MSG"

    @property
    def trusted(self) -> bool:
        return self in (Origin.USER, Origin.SYSTEM)


TRUSTED = frozenset({Origin.USER, Origin.SYSTEM})

Decision = Literal["ALLOW", "BLOCK", "ESCALATE"]

# Higher wins when aggregating ring verdicts.
SEVERITY: dict[str, int] = {"ALLOW": 0, "ESCALATE": 1, "BLOCK": 2}


def worst(*decisions: str) -> Decision:
    return max(decisions, key=lambda d: SEVERITY[d])  # type: ignore[return-value]


class ToolIntent(BaseModel):
    """What the agent asks permission to do."""

    session_id: str
    tool: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    justification: str = ""

    # The agent's *claim* about which prior outputs it used. The gateway
    # recomputes this independently (rings/ring1_provenance.py) and uses its
    # own answer -- a lying agent gains nothing. Kept on the wire because the
    # disagreement between claimed and computed is itself a signal.
    derived_from: list[str] = Field(default_factory=list)


class ToolResult(BaseModel):
    """What a tool returns. Every value carries its origin label (Ring 1)."""

    id: str
    tool: str
    origin: Origin
    value: str
    source: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)
    ok: bool = True

    @property
    def tainted(self) -> bool:
        return not self.origin.trusted


class RingResult(BaseModel):
    ring: int
    name: str
    decision: Decision
    score: int = 0
    reason: str = ""
    evidence: dict[str, Any] = Field(default_factory=dict)
    elapsed_ms: float = 0.0


class Verdict(BaseModel):
    intent_id: str
    session_id: str
    tool: str
    decision: Decision
    ring_results: list[RingResult] = Field(default_factory=list)
    reason: str = ""
    trust_after: int = 100
    caught_by: int | None = None

    # With enforcement off the gateway is pass-through: `decision` is ALLOW,
    # but the rings still run and `shadow_decision` records what they would
    # have said, so the cost of disabling it is visible rather than silent.
    enforced: bool = True
    shadow_decision: Decision | None = None
    elapsed_ms: float = 0.0

    def ring(self, n: int) -> RingResult | None:
        return next((r for r in self.ring_results if r.ring == n), None)
