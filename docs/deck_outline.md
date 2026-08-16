# Deck outline — 11 slides  (P7 / §7)

Minimum 18 pt. No animations. Verify every link before submitting.
Filename `TeamName_VYUHA.pptx`, under 10 MB.

Every number below comes from `results.json`. Regenerate with
`make benchmark` before exporting the deck, and never type a figure by hand.

---

**1 · Title**
VYUHA — a layered trust gateway for tool-using AI agents.
One line: *the checkpoint that stops an agent being turned against its owner by
a poisoned document.*
Team names, INNOVIK 6.0, PS-10.

**2 · The problem: the agent attack surface**
An agent that can read and act has no boundary between the two. Content it
merely *reads* becomes instructions it obeys. One diagram: user → agent →
tools, with a poisoned document entering at the read step.

**3 · Why existing defenses fail**
Classifiers judge what text *says*. Injections are written to be judged well.
Provenance judges where text *came from*, which the attacker does not control.
Land the line: *we don't classify the payload, we track its lineage.*

**4 · Architecture — the five rings** ← the most important slide
The gateway block diagram from the README. Rings 1–5, ALLOW/BLOCK/ESCALATE out
the bottom, executor below. Nothing else on this slide.

**5 · Rings 1 & 2 — the differentiators**
The data-taint / control-taint table. Then the A06 causal graph: six steps,
none suspicious, blocked at the sixth, all six named in the reason.
This is the slide that earns the score.

**6 · Tech stack**
FastAPI + Pydantic v2 · SQLAlchemy/SQLite · YAML policy · SHA-256 ledger ·
Jinja2 + SSE dashboard · pytest red-team suite. One line on each.
Note the three deliberate departures from plan (README table) if asked.

**7 · Trust ledger + verifiability**
The hash-chain formula, and the screenshot of `/verify` red with the entry
named. *You can edit the database. You cannot edit it quietly.*

**8 · Demo walkthrough**
Storyboard of the 4 minutes: attack succeeds → toggle → same attack blocked →
benign task passes → ledger tamper → results. Four screenshots, no text walls.

**9 · Results** ← second most important slide
12 → 0 attacks. 15/15 benign, 0 false positives. p95 13.3 ms. R1: 8, R2: 9.
Two bars, one table. Say the FP number out loud before anyone asks.

**10 · Limitations + roadmap**
Ring 4 is the weakest ring and the design does not depend on it — delete it and
all 12 attacks are still blocked. Ring 2's contextual branch is a heuristic.
0% FP is measured on 15 tasks, not production traffic.
Roadmap: Postgres, multi-tenancy, real connectors, signed attestation.

**11 · Impact, team, GitHub**
Who buys it (anyone deploying an agent with write access; middleware between
planner and executor), the team, the repo link. Test the link on a phone.
