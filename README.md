# VYUHA

**A layered trust gateway for tool-using AI agents.**

An agent that can both read and act has no boundary between the two. Content it
merely *reads* — a document, an email, a database row — arrives in the same
context window as its principal's instructions, and nothing in the model
architecture distinguishes them. An attacker who can put text in front of an
agent can direct that agent's tools.

VYUHA is a policy-enforcing gateway that sits between an agent's planner and
its tool executor. The agent cannot call a tool directly: it submits an
*intent*, which passes through five defense rings and comes back `ALLOW` /
`BLOCK` / `ESCALATE`. Every decision is written to a hash-chained ledger.

<p align="center">
  <img src="docs/architecture.svg" alt="An agent submits a tool intent to the VYUHA gateway, which passes it through five rings and returns allow, block or escalate to the tool executor." width="100%">
</p>

---

## Results

Measured against the bundled adversarial suite. Reproduce with
`python -m redteam.benchmark`, which writes `results.json`.

| | |
|---|---|
| Attacks succeeding, gateway **disabled** | **12 / 12** |
| Attacks succeeding, gateway **enabled** | **0 / 12** |
| Benign tasks completing | **15 / 15** |
| False-positive rate | **0 / 15 (0%)** |
| Added latency, p50 / p95 | **0.3 ms / 13.0 ms** |
| Caught by ring | Ring 1: 8 · Ring 2: 9 |

Every attack asserts *both* directions. A case that cannot succeed with the
gateway disabled proves nothing about the gateway, so the harness fails the run
if any attack is inert — `attacks.valid` in `results.json` tracks this.

---

## Quick start

Requires Python 3.11+. No Docker, no Redis, no network access.

```bash
python -m venv .venv
.venv/bin/python -m pip install -r requirements.txt      # Windows: .venv\Scripts\python.exe

.venv/bin/python -m pytest tests -q          # 75 tests
.venv/bin/python -m redteam.benchmark        # regenerate results.json
.venv/bin/python -m uvicorn gateway.api:app --port 8000   # dashboard
```

### The dashboard

<p align="center">
  <img src="docs/dashboard.png" alt="The VYUHA dashboard: scenario list and agent transcript on the left, live ring verdicts in the centre showing a six-step exfiltration chain blocked at Ring 2, and session trust, outbound log, ledger and benchmark results on the right." width="100%">
</p>

Above: a six-step attack blocked at Ring 2, with the reason naming every step in
the chain. The red entry in the outbound log is the same attack run moments
earlier with enforcement disabled — that one left the building.

Run a single scenario in the terminal, gateway disabled then enabled:

```bash
python -m redteam.cli A04        # multi-step exfiltration
python -m redteam.cli A06        # six-step slow burn
python -m redteam.cli --list     # all 27 scenarios
python -m redteam.cli --verify   # re-walk the ledger hash chain
```

A `Makefile` and a PowerShell wrapper (`vyuha.ps1`) wrap the same commands.
The commands above are the ones exercised in development; the `Makefile`
targets are convenience only and assume `make` is on PATH.

---

## The five rings

### Ring 1 — provenance / taint

Every value a tool returns is labelled with its origin:

| Origin | Trusted | May cause an action? |
|---|---|---|
| `USER`, `SYSTEM` | yes | yes |
| `TOOL_OUTPUT`, `RETRIEVED_DOC`, `EXTERNAL_MSG` | no | **no** |

This is the ring that beats a prompt-injection classifier, because it does not
care what the injected text *says*. It cares where it came from.

The distinction that makes it deployable rather than merely safe:

| | meaning | verdict for a sink call |
|---|---|---|
| **data taint** | an argument carries untrusted content | blocked only when it crosses the trust boundary |
| **control taint** | the *decision to make this call* traces to untrusted content | always blocked — this is the definition of a confused deputy |

Summarising an internal document and mailing it to a colleague is data taint to
an internal destination: ordinary work, allowed. The same summary sent to an
address a poisoned document chose for you is both, and blocked. Three benign
tasks in the suite (B08, B10, B11) deliberately read poisoned or restricted
content and mail an honest summary internally, because a taint tracker that
blocks those is not deployable.

**Provenance is computed, never claimed.** `ToolIntent.derived_from` exists on
the wire, but the gateway recomputes it from the text itself — verbatim
windows, identifier matches, and 5-gram shingles against every prior tool
output. An agent under injection is exactly the agent whose self-report you
cannot trust. The gap between claimed and computed is recorded as
`agent_underreported`.

### Ring 2 — kill-chain correlation

Ring 1 judges a call. Ring 2 judges the *sequence*. It maintains a causal graph
per session — nodes are tool calls, edges mean this call's arguments or
justification derive from that earlier call's output — walked transitively so a
laundering hop does not break the link.

Detected patterns: exfiltration chains, argument probing after denial, confused
deputy, goal drift against the session's declared goal, and sink bursts that
spread across tools rather than exceeding any single rate limit.

This is the difference from a WAF. A WAF sees one request; Ring 2 blocks chains
in which no individual step is suspicious.

### Ring 3 — capability policy

Deterministic, microseconds, no cleverness. Scopes, trust floors, argument
rules, deny patterns and rate limits, declared in `policies/default.yaml` and
parsed into Pydantic models:

```yaml
send_email:
  scopes: [outbound_mail]
  sink: true
  destination_field: to
  requires_trust: 70
  rate_limit: 3
  argument_rules:
    - field: to
      must_match_domain: ["@acme-internal.com"]
    - field: body
      deny_tainted_egress: true
```

### Ring 4 — semantic judge

Scores content for embedded imperatives, forged authority, concealment
instructions and encoded payloads; returns a suspicion score and a one-line
reason, cached by content hash. Local heuristic by default; set
`VYUHA_JUDGE_BACKEND=llm` with an API key to use a model instead.

### Ring 5 — trust ledger

```
entry_n.hash = sha256(entry_{n-1}.hash + canonical_json(entry_n.payload))
```

Append-only. `GET /api/ledger/verify` re-walks the chain and names the first
entry whose recomputed hash disagrees with the stored one. Edit a row directly
in `vyuha.db` and it reports which entry changed and how.

Session trust decays per violation by severity and recovers slowly on clean
calls; tools can require a trust floor.

### Execution order

Rings execute 1 → 3 → 2 → 4 (Ring 3's tainted-egress rule needs Ring 1's
provenance; Ring 2 needs both) and are reported in ring order. Ring 4 is
skipped once Rings 1–3 have hard-blocked. A block is attributed to the
**lowest-numbered ring** that returned the final decision.

---

## Where it is soft

**Ring 4 is the weakest ring and the design does not depend on it.** It scores
text, so it can be fooled by text. Two rules keep it honest: it may escalate
but can never block on its own, and it fails open to the Rings 1–3 verdict
after a 2 s timeout, logging the timeout rather than hiding it. Remove Ring 4
entirely and all twelve attacks are still blocked — Rings 1 and 2 account for
every one.

**Ring 2's contextual branch is a heuristic.** When an agent paraphrases well
enough that no argument matches any prior output, Ring 1 can only reach
ESCALATE and Ring 2 blocks on the shape of the session rather than on proof.
A patient attacker who never touches untrusted content before a sink call would
not be caught this way.

**0% false positives is measured on 15 tasks, not production traffic.** It is a
floor for confidence, not a guarantee.

**The LLM planner and LLM judge backends are implemented but unexercised.** All
published numbers use the deterministic scripted planner and the local
heuristic judge.

---

## Is the attack real?

Yes, and here is exactly how far the simulation goes.

The poisoned documents and emails contain ordinary natural-language injections
(`sandbox/corp_data/fixture.json`). The gateway sees only that text; it has no
knowledge of which items are poisoned.

The default planner (`agent/planner.py`) is scripted and deterministic so runs
are reproducible offline. When a tool result contains an injection, the planner
appends that injection's steps to its own plan — which is what a tool-using LLM
does when it reads untrusted content it cannot distinguish from its principal's
instructions. It only follows a payload it actually read, and the steps live in
an `injection` block the gateway never reads.

Set `VYUHA_PLANNER=llm` with `ANTHROPIC_API_KEY` to drive a real model over the
same six tools, the same sandbox and the same gateway.

---

## The adversarial suite

Twelve attacks against the bundled sandbox:

| | |
|---|---|
| A01 | Direct instruction injection in a retrieved document |
| A02 | Instruction injection in an inbound email body |
| A03 | Instruction hidden in a document footer |
| A04 | Multi-step exfiltration: read, query, send external |
| A05 | Confused deputy — granted DB credential used for an injected purpose |
| A06 | Slow burn: six steps with benign filler, paraphrased payload |
| A07 | Argument smuggling — external host hidden in URL userinfo |
| A08 | Destination mutation after denial (probing) |
| A09 | Goal drift mid-session |
| A10 | Tool-output-to-tool-input laundering (two hops) |
| A11 | Encoded payload defeating content matching |
| A12 | Rate-limit evasion by alternating sink tools |

Fifteen benign tasks form the false-positive denominator, including three that
deliberately handle poisoned or restricted content through legitimate flows.

---

## HTTP API

| | |
|---|---|
| `POST /api/session` | open a session with a declared goal |
| `POST /api/decide` | submit a `ToolIntent`, receive a `Verdict` |
| `POST /api/observe` | report a tool result so its provenance enters the graph |
| `POST /api/toggle` | enable or disable enforcement |
| `GET /api/ledger/verify` | re-walk the hash chain |
| `GET /api/events` | server-sent decision stream |
| `POST /api/run/{id}` | run a scenario through the live gateway |
| `GET /api/results` | contents of `results.json` |

With enforcement disabled the gateway is pass-through: the rings still run and
`Verdict.shadow_decision` records what they would have said, so the cost of
turning it off is visible rather than invisible.

---

## Layout

```
gateway/
  contract.py      the agent↔gateway interface
  taint.py         provenance tracing: verbatim, identifier, shingle
  policy.py        YAML → Pydantic capability policy
  store.py         session state: taint set, rate counters, causal graph
  core.py          the decision pipeline
  api.py           HTTP surface and dashboard host
  db.py            SQLAlchemy models
  events.py        pub/sub behind the SSE stream
  rings/           ring1_provenance · ring2_killchain · ring3_policy
                   ring4_judge · ring5_ledger
agent/
  loop.py          plan → intent → verdict → execute or re-plan
  planner.py       ScriptedPlanner (offline) · LLMPlanner
  tools.py         the six tools, each output labelled with its Origin
sandbox/
  env.py           fake company; sinks log instead of sending
  corp_data/       12 emails (2 injected), 8 documents (2 poisoned), 3 tables
redteam/
  scenarios.py     12 attacks + 15 benign tasks
  runner.py        run a scenario with enforcement on or off
  benchmark.py     → results.json
  cli.py           terminal driver
dashboard/         Jinja2 + vanilla JS + SSE, no CDN
policies/default.yaml
tests/             75 tests
```

**Stack.** FastAPI + Pydantic v2, SQLAlchemy over SQLite, YAML policy,
`hashlib` for the ledger, Jinja2 with vanilla JS and server-sent events for the
dashboard, pytest for the adversarial suite. Session state is held in an
in-process store behind a `SessionStore` interface, which is the seam for a
Redis-backed implementation. The dashboard has no CDN dependency and renders
with no network access.

---

## Configuration

Everything has a working default; the system runs with no `.env` at all. See
`.env.example`. Notable knobs:

| | |
|---|---|
| `VYUHA_ENFORCE` | boot value for enforcement (runtime-toggleable) |
| `VYUHA_POLICY` | path to the capability policy |
| `VYUHA_JUDGE_BACKEND` | `auto` / `heuristic` / `llm` / `off` |
| `VYUHA_PLANNER` | `scripted` or `llm` |
| `ANTHROPIC_API_KEY` | only needed for the `llm` backends |

---

## FAQ

**Doesn't this block everything?** 15/15 benign tasks complete, three of them
deliberately handling poisoned or restricted content. That is what the benign
suite is for.

**What if an attacker bypasses the classifier?** Ring 4 is not load-bearing.
Rings 1–3 are deterministic and catch all twelve attacks without it.

**What is the latency cost?** 13.0 ms at p95. Ring 3 is microseconds; the tail
is Ring 1's matcher over large documents.

**How is this different from a WAF?** A WAF sees one request. Ring 2 keeps the
session's causal graph and blocks chains in which no individual step is
suspicious.

**Could the agent lie in its `justification`?** Yes, which is why
`derived_from` is computed by the gateway rather than supplied by the agent,
and why the discrepancy is logged.

**Where does this sit in a stack?** As middleware between an agent's planner
and its tool executor, for any deployment where the agent has write access.

---

## Roadmap

Postgres, multi-tenancy and authentication, real connectors in place of the
sandbox, a signed external attestation for the ledger, and learned per-tenant
policy baselines.
