"""Tiny thread-safe pub/sub feeding the dashboard's SSE stream.

The rings run in a worker thread; the SSE endpoint is async. A plain
queue.Queue per subscriber keeps that boundary boring.
"""

from __future__ import annotations

import queue
import threading
import time
from typing import Any

_subscribers: list[queue.Queue] = []
_lock = threading.Lock()
_recent: list[dict[str, Any]] = []
MAX_RECENT = 200


def publish(kind: str, data: dict[str, Any]) -> None:
    event = {"kind": kind, "ts": time.time(), **data}
    with _lock:
        _recent.append(event)
        del _recent[:-MAX_RECENT]
        targets = list(_subscribers)
    for q in targets:
        try:
            q.put_nowait(event)
        except queue.Full:
            pass


def subscribe() -> queue.Queue:
    q: queue.Queue = queue.Queue(maxsize=500)
    with _lock:
        _subscribers.append(q)
    return q


def unsubscribe(q: queue.Queue) -> None:
    with _lock:
        if q in _subscribers:
            _subscribers.remove(q)


def recent(limit: int = 50) -> list[dict[str, Any]]:
    with _lock:
        return _recent[-limit:]
