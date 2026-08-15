"""Shared context threaded through the five rings."""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from ..contract import Origin, RingResult, ToolIntent
from ..policy import Policy
from ..store import CallNode, Session
from ..taint import Match


@dataclass
class RingContext:
    intent: ToolIntent
    session: Session
    policy: Policy
    node: CallNode

    # --- filled in by Ring 1, read by Rings 2-4 ------------------------
    data_matches: dict[str, list[Match]] = field(default_factory=dict)
    control_matches: list[Match] = field(default_factory=list)
    tainted_fields: set[str] = field(default_factory=set)
    origins: set[Origin] = field(default_factory=set)
    contextual_taint: bool = False
    destination: str | None = None
    destination_external: bool = False

    def arg_text(self) -> str:
        return "\n".join(f"{k}: {v}" for k, v in self.intent.arguments.items())

    @property
    def tainted_sources(self) -> list[str]:
        seen: list[str] = []
        for m in [*self.control_matches, *(m for ms in self.data_matches.values() for m in ms)]:
            if m.tainted and m.source not in seen:
                seen.append(m.source)
        return seen


class timed:
    """`with timed() as t:` -> t.ms"""

    def __enter__(self) -> "timed":
        self._t0 = time.perf_counter()
        self.ms = 0.0
        return self

    def __exit__(self, *exc: object) -> None:
        self.ms = (time.perf_counter() - self._t0) * 1000


def ok(ring: int, name: str, reason: str, ms: float = 0.0, **evidence) -> RingResult:
    return RingResult(
        ring=ring, name=name, decision="ALLOW", score=0, reason=reason,
        evidence=evidence, elapsed_ms=ms,
    )
