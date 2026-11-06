// CoinJoin CTF web demo: live transaction graph + protocol timeline. No build step, no deps.
const $ = (id) => document.getElementById(id);
const NS = "http://www.w3.org/2000/svg";
// An undefined manifest means initial state is still loading, not that setup is absent.
const S = { txs: [], u0: null, manifest: undefined, guess: [], reveal: null, entries: [], lastEntry: null, busy: null, fresh: new Set(), idles: 0, range: null, replaying: false };
const short = (h, n = 10) => (h && h.length > n ? h.slice(0, n) + "…" : h);
const btc = (s) => (s / 1e8).toFixed(4);
const hue = (v) => { let h = 7; for (const c of String(v)) h = (h * 31 + c.charCodeAt(0)) % 360; return h; };

function el(tag, attrs, parent) {
  const e = document.createElementNS(NS, tag);
  for (const k in attrs) e.setAttribute(k, attrs[k]);
  if (parent) parent.appendChild(e);
  return e;
}

// ---------- graph: one column per block, transactions stacked, outputs on the right edge ----------
const DOT = 7, PAD = 36, TXW = 16;
let renderQueued = false;
function scheduleRender() { if (!renderQueued) { renderQueued = true; requestAnimationFrame(() => { renderQueued = false; render(); }); } }

function render() {
  const svg = $("graph");
  svg.innerHTML = "";
  if (!S.txs.length) { svg.setAttribute("width", 0); return; }
  const spent = new Set();
  S.txs.forEach((t) => t.inputs.forEach((i) => spent.add(i.outpoint)));
  const heights = S.txs.map((t) => t.height);
  // A frozen history keeps its full width while it is replayed; a live stage grows.
  const h0 = S.range ? S.range[0] : Math.min(...heights), h1 = S.range ? S.range[1] : Math.max(...heights);
  // Fit the whole history in the visible width (scroll only for very long histories).
  const avail = $("graph-scroll").clientWidth - 2 * PAD - TXW - 20;
  const COL = Math.max(28, Math.min(120, Math.floor(avail / Math.max(h1 - h0, 1))));
  const colY = {}, pos = {};
  const layout = S.txs.map((t) => {
    const col = t.height - h0;
    const h = Math.max(t.outputs.length, t.inputs.length, 1) * DOT + 8;
    const y = colY[col] || PAD + 6;
    colY[col] = y + h + 16;
    const x = PAD + col * COL;
    t.outputs.forEach((o, k) => (pos[o.outpoint] = [x + TXW, y + 7 + k * DOT]));
    return { t, x, y, h };
  });
  svg.setAttribute("width", PAD * 2 + (h1 - h0) * COL + TXW + 20);
  svg.setAttribute("height", Math.max(...Object.values(colY)) + PAD);
  for (let hgt = h0; hgt <= h1; hgt++) {
    el("text", { x: PAD + (hgt - h0) * COL, y: 18 }, svg).textContent = `#${hgt}`;
  }
  const edges = el("g", {}, svg), nodes = el("g", {}, svg);
  const owners = S.reveal ? S.reveal.owners : {};
  const hostTx = new Set(S.reveal ? S.reveal.host_txids : []);
  const tips = new Set(S.reveal ? S.reveal.tips : []);
  const guess = new Set(S.guess);
  for (const { t, x, y, h } of layout) {
    t.inputs.forEach((i, k) => {
      const p = pos[i.outpoint];
      if (!p) return;
      const y2 = y + 6 + (k * (h - 12)) / Math.max(t.inputs.length - 1, 1);
      const cls = owners[i.outpoint] === "host" ? "edge lineage" : "edge";
      el("path", { d: `M${p[0]},${p[1]} C${p[0] + 45},${p[1]} ${x - 45},${y2} ${x},${y2}`, class: cls }, edges);
    });
    const cls = `tx ${t.kind}${hostTx.has(t.txid) ? " host" : ""}${S.fresh.has(t.txid) ? " new" : ""}`;
    const r = el("rect", { x, y, width: TXW, height: h, rx: 3, class: cls }, nodes);
    el("title", {}, r).textContent =
      `${t.kind} ${t.txid}\nblock ${t.height}, ${t.inputs.length} in, ${t.outputs.length} out` +
      (t.meta && t.meta.amount ? `\namount ${btc(t.meta.amount)} BTC, ${t.meta.makers || 0} makers` : "");
    const counts = {};
    t.outputs.forEach((o) => (counts[o.value] = (counts[o.value] || 0) + 1));
    for (const o of t.outputs) {
      const [cx, cy] = pos[o.outpoint];
      const eq = counts[o.value] > 1, unspent = !spent.has(o.outpoint), isU0 = o.outpoint === S.u0;
      const c = el("circle", {
        cx, cy, r: isU0 ? 5.5 : 3,
        class: ["out", unspent && "unspent", isU0 && "u0", guess.has(o.outpoint) && "sel",
                owners[o.outpoint] === "host" && "hostout", tips.has(o.outpoint) && "tip"].filter(Boolean).join(" "),
        fill: eq ? `hsl(${hue(t.txid + o.value)},65%,62%)` : "#6e7681",
      }, nodes);
      el("title", {}, c).textContent = `${o.outpoint}\n${btc(o.value)} BTC${unspent ? " (unspent)" : ""}${isU0 ? "\nU0: start here" : ""}`;
      if (unspent) c.addEventListener("click", () => toggleGuess(o.outpoint));
      if (isU0) el("text", { x: cx + 8, y: cy + 4, fill: "#f2c94c" }, nodes).textContent = "U0";
    }
  }
  S.fresh.clear();
}

function toggleGuess(op) {
  S.guess = S.guess.includes(op) ? S.guess.filter((g) => g !== op) : [...S.guess, op];
  renderGuess();
  render();
}

function renderGuess() {
  $("guess-list").innerHTML = S.guess.map((g) => `<li>${short(g.split(":")[0], 14)}:${g.split(":")[1]}</li>`).join("");
}

// ---------- protocol timeline ----------
let circuits = null;
function tl(html, cls = "") {
  const d = document.createElement("div");
  d.className = "ev " + cls;
  d.innerHTML = html;
  $("timeline").appendChild(d);
  d.scrollIntoView({ block: "nearest" });
  return d;
}
const tx = (id) => `<code title="${id}">${short(id)}</code>`;

const H = {
  stage_start() {
    Object.assign(S, { txs: [], u0: null, manifest: null, reveal: null, guess: [], entries: [], lastEntry: null, range: null });
    $("timeline").innerHTML = "";
    $("manifest").innerHTML = '<span class="muted">No game published yet.</span>';
    renderGuess(); render();
    tl("JoinMarket ecosystem starting on regtest", "head");
  },
  agents(e) {
    const bonded = e.makers.filter((m) => m.bond);
    tl(`${e.makers.length} makers (${bonded.length} with real timelocked fidelity bonds), ${e.takers} random takers, ` +
       `1 host running a tumbler schedule with random delays`);
  },
  tx(e) { S.txs.push(e.tx); S.fresh.add(e.tx.txid); scheduleRender(); },
  block(e) {
    $("graph-info").textContent = `block ${e.height}: ${S.txs.length} transactions so far`;
    const sc = $("graph-scroll"); sc.scrollLeft = sc.scrollWidth;
  },
  stage_done(e) {
    S.u0 = e.u0; S.range = [e.start_height, e.end_height];
    S.txs = S.txs.filter((t) => t.height >= e.start_height);  // drop warm-up blocks: same view as a reload
    render();
    $("graph-scroll").scrollLeft = 0;  // back to U0
    $("graph-info").textContent = `history frozen at blocks ${e.start_height}..${e.end_height}: ${e.txs} txs, ${e.outputs} outputs`;
    tl(`History frozen: <b>find U0's unspent tips in the committed wallet</b> ${tx(e.u0)}`, "ok");
  },
  proving(e) { tl(`Host proves the setup statement in RISC Zero (${e.dev ? "dev mode" : "real STARK"}, ${e.blocks} blocks)…`, "pending"); },
  setup(e) {
    const j = e.journal, m = e.manifest;
    tl(`Setup proof: ${e.cycles.toLocaleString()} cycles in ${e.seconds}s. Public journal: <b>${j.n_tips} tips</b>, ` +
       `com ${tx(j.com)}, wallet ${tx(j.wallet_commitment)}${shapeText(j, "<br>")}`, "ok");
    showManifest(m, e.fake ? "dev-mode receipt (fake seal)" : `real STARK receipt, proved in ${Math.round(e.seconds / 60)} min`, j);
  },
  entry(e) {
    S.lastEntry = e.name;
    tl(`Entry ${e.name}`, "head");
    tl(`Participant verified the setup proof against its own node${e.setup.fake ? " (dev receipt)" : ""}: ` +
       `the answer is the complete tip set for the declared wallet and range (${e.setup.n_tips} tips)`, "ok");
  },
  guess(e) { tl(`Guess: ${e.tips.length} outputs, x = ${tx(e.x)}`); },
  offer(e) {
    const d = tl(`Host commits to ${e.n} fresh garbled circuits (${e.and_gates.toLocaleString()} AND gates, ` +
                 `${(e.table_bytes / 1e6).toFixed(1)} MB each):<div class="circuits"></div>`);
    circuits = d.querySelector(".circuits");
    for (let i = 0; i < e.n; i++) circuits.insertAdjacentHTML("beforeend", `<span>${i}</span>`);
  },
  choose(e) {
    e.retained.forEach((i) => circuits.children[i].classList.add("kept"));
    tl(`Participant secretly keeps ${e.retained.join(", ")} (signed); host must open the other ${circuits.children.length - e.retained.length}`);
  },
  verified(e) {
    e.opened.forEach((i) => circuits.children[i].classList.add("opened"));
    tl(`${e.checked} opened circuits re-garbled and match their commitments (cheat chance 1/${Math.round(1 / e.cheat_probability)})`, "ok");
  },
  funded(e) { tl(`Funded ${tx(e.txid)}: entry ${btc(e.entry_fee)} + bounty ${btc(e.bounty)} BTC locked in the Taproot contract`); },
  asserted(e) {
    tl(`Assert ${tx(e.txid)} (${e.vsize} vB): guess bits committed on-chain with Lamport preimages` +
       `<div class="bits">${e.bits.map((b) => `<i class="${b ? "one" : ""}"></i>`).join("")}</div>`);
  },
  delivered(e) { tl(`Deliver ${tx(e.txid)} (${e.vsize} vB): ${e.labels} input labels, Script-checked against the asserted bits`); },
  evaluated(e) {
    e.instances.forEach((i) => circuits.children[i.instance].classList.add(i.win ? "win" : "lose"));
    tl(e.instances.map((i) => i.error ? `circuit ${i.instance}: ${i.error}` : `circuit ${i.instance}: win=${i.win} eq=${i.eq} o1=${i.o1}`).join("<br>"));
  },
  claimed(e) { tl(`<div class="banner win">WON: claimed ${btc(e.value)} BTC with the win label</div>`); },
  settled(e) { tl(`<div class="banner lose">Wrong guess: host settles ${btc(e.value)} BTC after the timelock</div>`); },
  timeout(e) { tl(`<div class="banner win">Host stalled: participant reclaims ${btc(e.value)} BTC</div>`); },
  audit(e) {
    tl(`Public audit of ${e.name}`, "head");
    tl(`<div class="verdict"><b>${e.verdict}</b><br><span class="muted">checked: choice signature, ${e.opened_checked} opened circuits, ` +
       `on-chain guess ${short(e.guess, 12)}, labels re-evaluated, setup proof. ` +
       `Conditional on an honest random selection; batch escape bound 1/${Math.round(1 / e.cheat_probability)}. ` +
       `The answer stays hidden.</span></div>`);
  },
  reveal(e) { S.reveal = e; render(); tl(`Revealed: ${e.host_txids.length} host transactions, tips highlighted in green`, "ok"); },
  error(e) { tl(e.message, "err"); },
  idle() { S.idles++; setBusy(null); },
};

// ---------- controls ----------
function proofText(p) {
  if (!p) return "no proof on file";
  if (p.error) return `proof INVALID: ${p.error}`;
  return p.fake ? "dev-mode receipt (fake seal)" : `real STARK receipt, verified in ${p.verify_ms} ms`;
}

// The lineage shape the setup proof discloses (minimums over the tips), from a verified journal.
function shapeText(j, prefix = "") {
  if (!j || j.tip_txs === undefined) return "";
  return `${prefix}<span class="proven">Proven: U0 was spent; ${j.n_tips} tips in ${j.tip_txs} txs, ` +
    `each ≥ ${j.min_depth} hops from U0, anonymity set ≥ ${j.min_anonymity}, ` +
    `≥ ${j.min_foreign_inputs} outside inputs per hop</span>`;
}

function showManifest(m, proof, journal) {
  S.manifest = m;
  $("manifest").innerHTML =
    `Bounty <b>${btc(m.bounty)} BTC</b>, entry fee ${btc(m.entry_fee)} BTC, ${m.n_tips} tips, ` +
    `${m.n_instances} circuits keep ${m.n_retained}, timelocks ${m.timeout_csv} blocks` +
    `<br><span class="muted">U0 ${short(m.history.u0, 18)}, blocks ${m.history.start_height}..${m.history.end_height}, ` +
    `${proof}</span>${shapeText(journal, "<br>")}`;
}

function setBusy(op) {
  S.busy = op;
  $("status").textContent = op ? `${op}…` : "idle";
  $("status").className = "badge" + (op ? " busy" : "");
  document.querySelectorAll("aside button").forEach((b) => (b.disabled = !!op));
}

async function post(path, body) {
  const r = await fetch(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body || {}) });
  if (!r.ok) { tl((await r.json()).detail || r.statusText, "err"); return; }
  setBusy((await r.json()).started);
}

$("btn-stage").onclick = () => post("/api/stage", { makers: 8, takers: 3, block_delay: 0.25 });
$("btn-setup").onclick = () => {
  if (S.manifest === undefined) return;
  if (S.manifest && !window.confirm(
    "A game is already set up. Regenerating its proof takes several minutes and replaces the current " +
    "commitment and proof. Existing entries cannot be audited against the new setup. Continue?"
  )) return;
  return post("/api/setup");
};
$("btn-play").onclick = () => {
  if (!S.guess.length) return tl("Select at least one unspent output", "err");
  post("/api/play", { tips: S.guess, stall: $("stall").checked });
};
$("btn-audit").onclick = () => (S.lastEntry ? post(`/api/audit/${S.lastEntry}`) : tl("No finished entry yet", "err"));
$("btn-reveal").onclick = () => post("/api/reveal");
$("btn-replay").onclick = replay;
$("btn-clear").onclick = () => { S.guess = []; renderGuess(); render(); };
for (const [id, kind] of [["btn-near", "near_miss"], ["btn-correct", "correct"]]) {
  $(id).onclick = async () => {
    const r = await fetch(`/api/demo-guess/${kind}`);
    if (!r.ok) return tl((await r.json()).detail, "err");
    S.guess = await r.json(); renderGuess(); render();
  };
}

async function init() {
  const st = await (await fetch("/api/state")).json();
  S.manifest = st.manifest;
  if (st.stage) {
    S.txs = st.stage.txs; S.u0 = st.stage.u0; render();
    $("graph-info").textContent = `blocks ${st.stage.start_height}..${st.stage.end_height}: ${S.txs.length} transactions`;
  }
  if (st.stage) {
    S.range = [st.stage.start_height, st.stage.end_height];
    tl(`History frozen at blocks ${st.stage.start_height}..${st.stage.end_height}: ` +
       `<b>find every unspent descendant of U0</b> ${tx(st.stage.u0)}`, "ok");
  }
  if (st.manifest) {
    showManifest(st.manifest, proofText(st.proof), st.proof && st.proof.journal);
    tl(`Game published: ${st.manifest.n_tips} tips committed, ${proofText(st.proof)}`, "ok");
  }
  S.lastEntry = st.entries.length ? st.entries[st.entries.length - 1] : null;
  setBusy(st.busy);
  const es = new EventSource(`/api/events?since=${st.offset}`);
  es.onmessage = (m) => { const e = JSON.parse(m.data); (H[e.kind] || (() => {}))(e); };
  es.onerror = () => { $("status").textContent = "reconnecting"; };
}
// Animate a frozen history block by block (for a precomputed game: same view as a live stage).
async function replay() {
  if (S.replaying || !S.txs.length) return;
  S.replaying = true;
  const all = S.txs.slice().sort((a, b) => a.height - b.height);
  const heights = [...new Set(all.map((t) => t.height))];
  S.txs = [];
  for (const h of heights) {
    for (const t of all) if (t.height === h) { S.txs.push(t); S.fresh.add(t.txid); }
    render();
    $("graph-info").textContent = `block ${h}: ${S.txs.length} transactions so far`;
    await new Promise((r) => setTimeout(r, 300));
  }
  $("graph-info").textContent = `history frozen at blocks ${heights[0]}..${heights[heights.length - 1]}: ${S.txs.length} txs`;
  S.replaying = false;
}

window.addEventListener("resize", scheduleRender);
init();
