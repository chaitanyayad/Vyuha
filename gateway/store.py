"""Per-session state: taint set, rate counters, causal graph.

Backed by process memory behind a key-shaped interface, so a fresh clone needs
nothing installed and nothing running. `SessionStore` is the seam: swap in a
Redis-backed implementation without touching the rings.
"""

from __future__ import annotations

import threading
import time
from collections import Counter
from dataclasses import dataclass, field

from .contract import Origin, ToolResult


@dataclass
class CallNode:
    """One node of the session's causal graph (Ring 2)."""

    id: str
    index: int
    tool: str
    arguments: dict
    justification: str
    derived_from: list[str] = field(default_factory=list)
    origins: set[Origin] = field(default_factory=set)
    decision: str = "PENDING"
    caught_by: int | None = None
    reason: str = ""
    destination: str | None = None
    destination_external: bool = False
    ts: float = field(default_factory=time.time)

    @property
    def tainted(self) -> bool:
        return any(not o.trusted for o in self.origins)


@dataclass
class Session:
    id: str
    goal: str = ""
    trust: int = 100
    enforced: bool = True
    started_at: float = field(default_factory=time.time)

    outputs: dict[str, ToolResult] = field(default_factory=dict)
    nodes: list[CallNode] = field(default_factory=list)
    # output id -> id of the call node that produced it, so Ring 2 can walk
    # provenance transitively across laundering hops.
    owner: dict[str, str] = field(default_factory=dict)
    rates: Counter = field(default_factory=Counter)
    seq: int = 0

    def record_output(self, node_id: str, result: ToolResult) -> None:
        self.outputs[result.id] = result
        self.owner[result.id] = node_id

    def ancestors(self, node: "CallNode") -> list["CallNode"]:
        """Every earlier call this one transitively depends on, oldest first."""
        seen: set[str] = set()
        frontier = list(node.derived_from)
        found: list[CallNode] = []
        while frontier:
            out_id = frontier.pop()
            owner_id = self.owner.get(out_id)
            if not owner_id or owner_id in seen:
                continue
            seen.add(owner_id)
            parent = self.node(owner_id)
            if parent is None:
                continue
            found.append(parent)
            frontier.extend(parent.derived_from)
        return sorted(found, key=lambda n: n.index)

    def next_id(self, prefix: str) -> str:
        self.seq += 1
        return f"{prefix}_{self.seq}"

    @property
    def tainted_outputs(self) -> list[ToolResult]:
        return [o for o in self.outputs.values() if o.tainted]

    def node(self, node_id: str) -> CallNode | None:
        return next((n for n in self.nodes if n.id == node_id), None)

    def denials(self, tool: str | None = None) -> list[CallNode]:
        return [
            n
            for n in self.nodes
            if n.decision in ("BLOCK", "ESCALATE") and (tool is None or n.tool == tool)
        ]


class SessionStore:
    def __init__(self) -> None:
        self._sessions: dict[str, Session] = {}
        self._lock = threading.RLock()

    def open(self, session_id: str, goal: str = "", trust: int = 100) -> Session:
        with self._lock:
            s = Session(id=session_id, goal=goal, trust=trust)
            self._sessions[session_id] = s
            return s

    def get(self, session_id: str) -> Session:
        with self._lock:
            s = self._sessions.get(session_id)
            if s is None:
                s = self.open(session_id)
            return s

    def all(self) -> list[Session]:
        with self._lock:
            return list(self._sessions.values())

    def drop(self, session_id: str) -> None:
        with self._lock:
            self._sessions.pop(session_id, None)

    def clear(self) -> None:
        with self._lock:
            self._sessions.clear()


STORE = SessionStore()
