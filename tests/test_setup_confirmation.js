const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const { join } = require("node:path");
const { test } = require("node:test");
const vm = require("node:vm");

const script = readFileSync(join(__dirname, "../src/coinjoinctf/static/app.js"), "utf8");
const manifest = {
  bounty: 10000000, entry_fee: 100000, n_tips: 3, n_instances: 20, n_retained: 3, timeout_csv: 6,
  history: { u0: "abc:0", start_height: 1, end_height: 31 },
};

// Execute the shipped browser script, with only DOM, dialog and network boundaries stubbed.
function page(existing, accept = false) {
  const nodes = new Map(), requests = [], dialogs = [];
  const element = () => ({
    innerHTML: "", textContent: "", disabled: false,
    setAttribute() {}, appendChild() {}, scrollIntoView() {},
  });
  const get = (id) => {
    if (!nodes.has(id)) nodes.set(id, element());
    return nodes.get(id);
  };
  let initialResponse, stream;
  const initial = new Promise((resolve) => { initialResponse = resolve; });
  const context = vm.createContext({
    document: {
      getElementById: get, createElement: element,
      querySelectorAll: () => [...nodes.values()],
    },
    window: {
      addEventListener() {},
      confirm: (message) => { dialogs.push(message); return accept; },
    },
    EventSource: class { constructor() { stream = this; } },
    fetch: (path, options) => {
      if (path === "/api/state") return initial;
      requests.push({ path, options });
      return Promise.resolve({ ok: true, json: async () => ({ started: "setup" }) });
    },
  });
  vm.runInContext(script, context);
  return {
    requests, dialogs,
    click: () => get("btn-setup").onclick(),
    event: (event) => stream.onmessage({ data: JSON.stringify(event) }),
    async ready() {
      initialResponse({ json: async () => ({
        stage: null, manifest: existing, proof: null, entries: [], busy: null, offset: 0,
      }) });
      await new Promise(setImmediate);
    },
  };
}

test("unknown initial state cannot start expensive setup", () => {
  const p = page(manifest, true);
  p.click();
  assert.equal(p.requests.length, 0);
  assert.equal(p.dialogs.length, 0);
});

test("first setup needs no regeneration confirmation", async () => {
  const p = page(null);
  await p.ready();
  await p.click();
  assert.equal(p.dialogs.length, 0);
  assert.equal(p.requests.length, 1);
  assert.equal(p.requests[0].path, "/api/setup");
  assert.equal(p.requests[0].options.method, "POST");
});

test("canceling regeneration sends no request", async () => {
  const p = page(manifest);
  await p.ready();
  await p.click();
  assert.equal(p.requests.length, 0);
  assert.equal(p.dialogs.length, 1);
  assert.match(p.dialogs[0], /several minutes/);
  assert.match(p.dialogs[0], /replaces the current commitment and proof/);
  assert.match(p.dialogs[0], /Existing entries cannot be audited/);
});

test("confirmed regeneration sends exactly one request", async () => {
  const p = page(manifest, true);
  await p.ready();
  await p.click();
  assert.equal(p.dialogs.length, 1);
  assert.equal(p.requests.length, 1);
  assert.equal(p.requests[0].path, "/api/setup");
});

test("live setup completion also enables the regeneration warning", async () => {
  const p = page(null);
  await p.ready();
  p.event({ kind: "setup", manifest, journal: { n_tips: 3, com: "abc", wallet_commitment: "def" },
    cycles: 1000, seconds: 1, fake: true });
  await p.click();
  assert.equal(p.dialogs.length, 1);
  assert.equal(p.requests.length, 0);
});

test("a new stage clears the previous setup state", async () => {
  const p = page(manifest);
  await p.ready();
  p.event({ kind: "stage_start" });
  await p.click();
  assert.equal(p.dialogs.length, 0);
  assert.equal(p.requests.length, 1);
});
