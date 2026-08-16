"""Benchmark harness.

    python -m redteam.benchmark   ->   results.json

One command produces every published number, so any write-up and the repo read
from the same file and cannot disagree.
"""

from __future__ import annotations

import json
import sys
import time
from collections import Counter
from pathlib import Path

from gateway.settings import ROOT

from .runner import latency_stats, run_scenario
from .scenarios import ATTACKS, BENIGN

OUT = ROOT / "results.json"


def run(persist: bool = True) -> dict:
    started = time.time()
    attack_rows, benign_rows = [], []
    latencies: list[float] = []
    attribution: Counter = Counter()

    for sc in ATTACKS:
        off = run_scenario(sc, enforced=False, persist=persist)
        on = run_scenario(sc, enforced=True, persist=persist)
        latencies.extend(on.latencies)
        rings = on.rings_that_caught
        for ring in rings:
            attribution[ring] += 1
        attack_rows.append({
            "id": sc.id, "name": sc.name, "category": sc.category,
            "succeeded_off": off.attack_succeeded,
            "succeeded_on": on.attack_succeeded,
            "blocked": not on.attack_succeeded,
            "caught_by": rings,
            "expect_ring": sc.expect_ring,
            "reason": on.block_reason,
            "steps": len(on.report.traces),
            "trust_after": on.report.trust,
            # A case that cannot succeed with the gateway off proves nothing.
            "valid": off.attack_succeeded,
        })

    for sc in BENIGN:
        on = run_scenario(sc, enforced=True, persist=persist)
        latencies.extend(on.latencies)
        benign_rows.append({
            "id": sc.id, "name": sc.name, "category": sc.category,
            "completed": on.benign_completed,
            "steps": len(on.report.traces),
            "false_positive": not on.benign_completed,
            "reason": on.block_reason,
        })

    succeeded_off = sum(r["succeeded_off"] for r in attack_rows)
    succeeded_on = sum(r["succeeded_on"] for r in attack_rows)
    false_positives = sum(r["false_positive"] for r in benign_rows)

    return {
        "generated_at": time.time(),
        "duration_s": round(time.time() - started, 2),
        "attacks": {
            "total": len(attack_rows),
            "valid": sum(r["valid"] for r in attack_rows),
            "succeeded_vyuha_off": succeeded_off,
            "succeeded_vyuha_on": succeeded_on,
            "blocked": len(attack_rows) - succeeded_on,
            "success_rate_off": round(succeeded_off / len(attack_rows), 4),
            "success_rate_on": round(succeeded_on / len(attack_rows), 4),
            "rows": attack_rows,
        },
        "benign": {
            "total": len(benign_rows),
            "completed": len(benign_rows) - false_positives,
            "false_positives": false_positives,
            "false_positive_rate": round(false_positives / len(benign_rows), 4),
            "rows": benign_rows,
        },
        "ring_attribution": {str(k): v for k, v in sorted(attribution.items())},
        "latency_ms": latency_stats(latencies),
    }


def main() -> int:
    results = run()
    OUT.write_text(json.dumps(results, indent=2), encoding="utf-8")

    a, b, lat = results["attacks"], results["benign"], results["latency_ms"]
    print()
    print("  VYUHA benchmark")
    print("  " + "-" * 52)
    print(f"  attacks succeeding, VYUHA off   {a['succeeded_vyuha_off']}/{a['total']}")
    print(f"  attacks succeeding, VYUHA on    {a['succeeded_vyuha_on']}/{a['total']}")
    print(f"  benign tasks completing         {b['completed']}/{b['total']}")
    print(f"  false-positive rate             {b['false_positives']}/{b['total']}"
          f"  ({b['false_positive_rate']:.1%})")
    print(f"  gateway latency  p50 / p95      {lat['p50']:.1f} ms / {lat['p95']:.1f} ms")
    print(f"  caught by ring                  "
          + ", ".join(f"R{k}: {v}" for k, v in results["ring_attribution"].items()))
    print("  " + "-" * 52)
    print(f"  wrote {OUT}")
    print()

    if a["valid"] < a["total"]:
        bad = [r["id"] for r in a["rows"] if not r["valid"]]
        print(f"  WARNING: attacks that do not succeed even with VYUHA off: {bad}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
