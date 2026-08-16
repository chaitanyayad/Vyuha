"""Terminal driver for a single scenario.

    python -m redteam.cli A04          run one scenario, gateway off then on
    python -m redteam.cli A04 --live   run it through a running server (:8000)
    python -m redteam.cli --verify     re-walk the ledger chain
    python -m redteam.cli --reset      wipe and reseed

The --live form drives the same gateway the dashboard is watching, so a run
started from the terminal appears in the browser as it happens.
"""

from __future__ import annotations

import argparse
import sys

from gateway.db import reset_db
from gateway.rings.ring5_ledger import verify

from .runner import Outcome, run_scenario
from .scenarios import ALL, by_id

W = 78
DEC = {"ALLOW": "ALLOW   ", "BLOCK": "BLOCK   ", "ESCALATE": "ESCALATE"}


def rule(char: str = "─") -> None:
    print("  " + char * W)


def wrap(text: str, indent: int = 8, width: int = W) -> str:
    words, lines, line = text.split(), [], ""
    for word in words:
        if len(line) + len(word) + 1 > width - indent:
            lines.append(line)
            line = word
        else:
            line = f"{line} {word}".strip()
    lines.append(line)
    return ("\n" + " " * indent).join(lines)


def show(outcome: Outcome, label: str) -> None:
    print()
    rule("═")
    print(f"  {label}")
    rule("═")
    for trace in outcome.report.traces:
        verdict = trace.verdict
        shown = verdict.shadow_decision or verdict.decision
        mark = "·" if verdict.decision == "ALLOW" and not verdict.shadow_decision else "!"
        rings = "".join(
            str(r.ring) if r.decision == "ALLOW" else f"[{r.ring}]"
            for r in verdict.ring_results
        )
        print(f"  {mark} {trace.step}. {trace.tool:<12} {DEC.get(shown, shown)}  "
              f"rings {rings}  {verdict.elapsed_ms:5.1f}ms  trust {verdict.trust_after}")
        if shown != "ALLOW":
            print(f"        {wrap(verdict.reason)}")
        if not verdict.enforced and verdict.shadow_decision:
            print("        ^ gateway is OFF: this ran anyway")

    leaked = outcome.leaked
    print()
    if leaked:
        print("  OUTBOUND LOG — data that left acme-internal.com:")
        for d in leaked:
            print(f"      {wrap(d.summary(200), 6)}")
    else:
        print("  OUTBOUND LOG — nothing left the building.")
    print(f"  session trust: {outcome.report.trust}/100")


def run(scenario_id: str, live: bool) -> int:
    scenario = by_id(scenario_id)
    print()
    print(f"  {scenario.id} · {scenario.name}")
    print(f"  goal: {scenario.goal}")
    if scenario.notes:
        print(f"  note: {wrap(scenario.notes, 8)}")

    if live:
        import httpx

        resp = httpx.post(f"http://127.0.0.1:8000/api/run/{scenario.id}", timeout=60)
        resp.raise_for_status()
        data = resp.json()
        print()
        print(f"  ran on the live gateway (enforced={data['enforced']})")
        print(f"  session {data['session_id']} · caught by rings {data['caught_by']}")
        for line in data["leaked"]:
            print(f"      LEAKED: {line}")
        if not data["leaked"]:
            print("      nothing left the building")
        return 0

    off = run_scenario(scenario, enforced=False, persist=False)
    show(off, "VYUHA OFF — pass-through")
    on = run_scenario(scenario, enforced=True, persist=True)
    show(on, "VYUHA ON — enforcing")

    print()
    rule()
    verdict = ("attack blocked" if off.attack_succeeded and not on.attack_succeeded
               else "NO CHANGE — check this case" if off.attack_succeeded
               else "benign task unaffected" if on.benign_completed
               else "benign task was interfered with")
    print(f"  {verdict}")
    rule()
    print()
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="redteam.cli")
    parser.add_argument("scenario", nargs="?", help="scenario id, e.g. A04 or B01")
    parser.add_argument("--live", action="store_true",
                        help="run through the server on :8000 so the dashboard sees it")
    parser.add_argument("--verify", action="store_true", help="re-walk the ledger chain")
    parser.add_argument("--reset", action="store_true", help="wipe and reseed the database")
    parser.add_argument("--list", action="store_true", help="list scenarios")
    args = parser.parse_args()

    if args.reset:
        reset_db()
        print("  database wiped and reseeded")
        return 0

    if args.verify:
        report = verify()
        print()
        print(f"  ledger: {'VALID' if report['valid'] else 'BROKEN'}  "
              f"({report['entries']} entries)")
        print(f"  {wrap(report['detail'], 2)}")
        print()
        return 0 if report["valid"] else 1

    if args.list or not args.scenario:
        for s in ALL:
            print(f"  {s.id}  {s.category:<16} {s.name}")
        return 0

    return run(args.scenario, args.live)


if __name__ == "__main__":
    sys.exit(main())
