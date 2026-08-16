/* VYUHA dashboard. Vanilla JS + EventSource — nothing to install and nothing
   fetched from a CDN at runtime. */

const $ = (id) => document.getElementById(id);
const RINGS = { 1: "provenance", 2: "kill-chain", 3: "policy", 4: "judge" };

let enforced = $("enforce").checked;

/* ── helpers ─────────────────────────────────────────────── */

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function push(container, node, keep = 60) {
  const empty = container.querySelector(".empty");
  if (empty) empty.remove();
  container.prepend(node);
  while (container.children.length > keep) container.lastElementChild.remove();
}

function el(html) {
  const t = document.createElement("template");
  t.innerHTML = html.trim();
  return t.content.firstElementChild;
}

/* Pull out the filenames and addresses a reason mentions, so the specific
   source of a block is the first thing the eye lands on. */
function highlight(reason) {
  return esc(reason).replace(
    /((?:doc|db|email):[^\s,)]+|[\w.+-]+@[\w.-]+\.\w+|https?:\/\/[^\s,)]+)/g,
    "<strong>$1</strong>");
}

/* ── scenarios ───────────────────────────────────────────── */

async function loadScenarios() {
  const list = await (await fetch("/api/scenarios")).json();
  for (const s of list) {
    const chip = el(`<button class="chip ${s.kind}" title="${esc(s.name)}\n\n${esc(s.goal)}${
      s.notes ? "\n\n" + esc(s.notes) : ""}">${esc(s.id)}</button>`);
    chip.onclick = () => runScenario(s, chip);
    ($(s.kind === "attack" ? "attacks" : "benign")).appendChild(chip);
  }
}

async function runScenario(scenario, chip) {
  document.querySelectorAll(".chip").forEach((c) => (c.disabled = true));
  chip.classList.add("running");
  try {
    const res = await fetch(`/api/run/${scenario.id}`, { method: "POST" });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "run failed");
    refreshOutbox();
    refreshLedger();
  } catch (err) {
    push($("verdicts"), el(`<div class="card block"><div class="reason">${esc(err.message)}</div></div>`));
  } finally {
    chip.classList.remove("running");
    document.querySelectorAll(".chip").forEach((c) => (c.disabled = false));
  }
}

/* ── event stream ────────────────────────────────────────── */

function onSessionOpen(e) {
  push($("transcript"), el(`
    <div class="card">
      <div class="card-head"><span class="tool">${esc(e.scenario || "session")}</span>
        <span class="verdict ${e.enforced ? "allow" : "escalate"}">${e.enforced ? "VYUHA ON" : "VYUHA OFF"}</span></div>
      <p class="goal">${esc(e.goal)}</p>
    </div>`));
  $("trust-note").textContent = e.scenario ? `${e.scenario} — ${e.session_kind}` : "running";
}

function onToolOutput(e) {
  const untrusted = ["TOOL_OUTPUT", "RETRIEVED_DOC", "EXTERNAL_MSG"].includes(e.origin);
  push($("transcript"), el(`
    <div class="card allow">
      <div class="card-head">
        <span class="tool">${esc(e.tool)}</span>
        <span class="origin ${untrusted ? "untrusted" : ""}">${esc(e.origin)}</span>
      </div>
      <div class="meta">${esc(e.source)}</div>
      <p class="reason">${esc(e.preview)}</p>
    </div>`));
}

function onDecision(e) {
  const v = e.verdict;
  const cls = v.decision.toLowerCase();
  const passthru = v.enforced === false && v.shadow_decision && v.shadow_decision !== "ALLOW";

  const badges = [1, 2, 3, 4].map((n) => {
    const r = (v.ring_results || []).find((x) => x.ring === n);
    if (!r) return `<span class="rb" title="ring ${n} — not reached">${n}</span>`;
    const caught = v.caught_by === n ? " caught" : "";
    return `<span class="rb ${r.decision.toLowerCase()}${caught}" title="ring ${n} · ${RINGS[n]}\n${
      r.decision} (score ${r.score})\n${r.reason}">${n}</span>`;
  }).join("");

  const label = passthru ? `WOULD ${v.shadow_decision}` : v.decision;
  const labelCls = passthru ? v.shadow_decision.toLowerCase() : cls;

  const ring2 = (v.ring_results || []).find((r) => r.ring === 2);
  const chain = ring2 && ring2.evidence && ring2.evidence.steps && ring2.decision !== "ALLOW"
    ? `<div class="chain">chain: ${esc(ring2.evidence.steps.join("  →  "))}</div>` : "";

  const sources = (e.tainted_sources || []).length
    ? `<div class="meta">tainted sources: ${esc(e.tainted_sources.join(", "))}</div>` : "";

  const card = el(`
    <div class="card ${passthru ? "passthru" : cls} ${cls === "block" ? "flash" : ""}">
      <div class="card-head">
        <span class="tool">${esc(v.tool)}</span>
        <span class="verdict ${labelCls}">${esc(label)}</span>
        <span class="ring-badges">${badges}</span>
      </div>
      <p class="reason">${highlight(v.reason)}</p>
      ${chain}${sources}
      <div class="meta">${v.elapsed_ms.toFixed(1)} ms · trust ${v.trust_after}${
        e.ledger_seq ? ` · ledger #${e.ledger_seq} ${esc(String(e.ledger_hash).slice(0, 10))}…` : ""}</div>
    </div>`);
  push($("verdicts"), card);
  setTrust(v.trust_after);
}

function setTrust(value) {
  $("trust-value").textContent = value;
  const fill = $("trust-fill");
  fill.style.width = `${Math.max(0, Math.min(100, value))}%`;
  fill.className = "fill" + (value < 45 ? " bad" : value < 80 ? " warn" : "");
}

function connect() {
  const source = new EventSource("/api/events");
  source.onmessage = (msg) => {
    const e = JSON.parse(msg.data);
    if (e.kind === "session_open") onSessionOpen(e);
    else if (e.kind === "tool_output") onToolOutput(e);
    else if (e.kind === "decision") onDecision(e);
    else if (e.kind === "toggle") applyToggle(e.enforced);
    else if (e.kind === "session_close") refreshLedger();
  };
  source.onerror = () => setTimeout(() => { source.close(); connect(); }, 2000);
}

/* ── enforcement toggle ──────────────────────────────────── */

function applyToggle(on) {
  enforced = on;
  $("enforce").checked = on;
  $("toggle-label").textContent = on ? "VYUHA ON" : "VYUHA OFF";
  document.body.classList.toggle("unguarded", !on);
}

$("enforce").addEventListener("change", async (ev) => {
  const res = await fetch(`/api/toggle?on=${ev.target.checked}`, { method: "POST" });
  applyToggle((await res.json()).enforced);
});

/* ── ledger, outbox, results ─────────────────────────────── */

async function verifyChain() {
  const r = await (await fetch("/api/ledger/verify")).json();
  const pill = $("ledger-pill");
  pill.className = "pill " + (r.valid ? "good" : "bad");
  pill.title = r.detail;
  $("ledger-text").textContent = r.valid
    ? `ledger ok · ${r.entries}`
    : `ledger BROKEN @ #${r.broken_at}`;
  if (!r.valid) {
    push($("verdicts"), el(`
      <div class="card block flash">
        <div class="card-head"><span class="tool">ledger/verify</span>
          <span class="verdict block">TAMPERED</span></div>
        <p class="reason">${esc(r.detail)}</p>
      </div>`));
  }
  return r;
}

async function refreshLedger() {
  const rows = await (await fetch("/api/ledger?limit=12")).json();
  const box = $("ledger");
  box.innerHTML = rows.length ? "" : '<p class="empty">No entries yet.</p>';
  for (const r of rows) {
    box.appendChild(el(`<div class="row">#${r.seq} ${esc(r.payload.tool)} · ${
      esc(r.payload.decision)}${r.payload.caught_by ? ` R${r.payload.caught_by}` : ""}
      <span class="hash">${esc(r.hash.slice(0, 12))}…</span></div>`));
  }
  verifyChain();
}

async function refreshOutbox() {
  const rows = await (await fetch("/api/outbox")).json();
  const box = $("outbox");
  box.innerHTML = rows.length ? "" : '<p class="empty">Nothing has been sent.</p>';
  for (const d of rows.slice(0, 12)) {
    box.appendChild(el(`<div class="row ${d.external ? "external" : ""}">${
      d.external ? "⚠ LEFT THE BUILDING · " : ""}${esc(d.destination)}<br>${
      esc((d.subject ? d.subject + " — " : "") + d.body).slice(0, 160)}</div>`));
  }
}

async function refreshResults() {
  const res = await fetch("/api/results");
  if (!res.ok) return;
  const r = await res.json();
  const a = r.attacks, b = r.benign, lat = r.latency_ms;
  const pct = (n, d) => (d ? Math.round((100 * n) / d) : 0);
  $("results").innerHTML = `
    <div class="bars">
      <div class="bar-row"><span class="lbl">VYUHA off</span>
        <span class="bar-track"><span class="bar-fill off" style="width:${pct(a.succeeded_vyuha_off, a.total)}%"></span></span>
        <span class="num">${a.succeeded_vyuha_off}/${a.total}</span></div>
      <div class="bar-row"><span class="lbl">VYUHA on</span>
        <span class="bar-track"><span class="bar-fill on" style="width:${pct(a.succeeded_vyuha_on, a.total)}%"></span></span>
        <span class="num">${a.succeeded_vyuha_on}/${a.total}</span></div>
    </div>
    <div class="stat"><span class="k">attacks succeeding</span><span class="v">${
      a.succeeded_vyuha_off} → ${a.succeeded_vyuha_on}</span></div>
    <div class="stat"><span class="k">false positives</span><span class="v">${
      b.false_positives}/${b.total}</span></div>
    <div class="stat"><span class="k">added latency p50 / p95</span><span class="v">${
      lat.p50.toFixed(1)} / ${lat.p95.toFixed(1)} ms</span></div>
    <div class="stat"><span class="k">caught by ring</span><span class="v">${
      Object.entries(r.ring_attribution).map(([k, v]) => `R${k}:${v}`).join("  ")}</span></div>`;
}

/* ── boot ────────────────────────────────────────────────── */

$("verify-btn").onclick = verifyChain;
$("reset-btn").onclick = async () => {
  await fetch("/api/reset", { method: "POST" });
  $("transcript").innerHTML = '<p class="empty">Sandbox reset.</p>';
  $("verdicts").innerHTML = '<p class="empty">Sandbox reset. Run a scenario.</p>';
  setTrust(100);
  refreshOutbox();
  refreshLedger();
};

applyToggle(enforced);
setTrust(100);
loadScenarios();
refreshOutbox();
refreshLedger();
refreshResults();
connect();
