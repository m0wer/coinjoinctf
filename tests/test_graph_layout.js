const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const { join } = require("node:path");
const { test } = require("node:test");
const vm = require("node:vm");

// Load the shipped browser script with inert DOM and network stubs, then call its pure functions.
function load() {
  const element = () => ({ innerHTML: "", textContent: "", setAttribute() {}, appendChild() {}, scrollIntoView() {} });
  const context = vm.createContext({
    document: { getElementById: element, createElement: element, querySelectorAll: () => [] },
    window: { addEventListener() {} },
    EventSource: class {},
    fetch: () => new Promise(() => {}),
  });
  vm.runInContext(readFileSync(join(__dirname, "../src/coinjoinctf/static/app.js"), "utf8"), context);
  return context;
}

const { layout, trace, classifyGuess } = load();

// A coinjoin per block, each with `outs` outputs; output k of block n is spent in block n + 1.
function history(blocks, outs, start = 100) {
  const txs = [];
  for (let n = 0; n < blocks; n++) {
    const txid = `t${n}`;
    txs.push({
      txid, kind: "coinjoin", height: start + n,
      inputs: n ? [{ outpoint: `t${n - 1}:0` }] : [{ outpoint: "u0:0" }],
      outputs: Array.from({ length: outs }, (_, k) => ({ outpoint: `${txid}:${k}`, value: 1000 })),
    });
  }
  return txs;
}

test("a small history grows its dots to fill the viewport, without scrolling", () => {
  const txs = history(10, 6);
  const L = layout(txs, [100, 109], 1100, 800);
  assert.equal(L.dot, 24);
  assert.equal(L.r, 9);
  assert.ok(L.width <= 1100 && L.height <= 800, `${L.width}x${L.height}`);
});

test("the tallest block column sets the row pitch so the whole history fits", () => {
  const txs = history(30, 4);
  for (let k = 0; k < 3; k++) {  // one crowded block: three 13-output coinjoins
    txs.push({ txid: `big${k}`, kind: "coinjoin", height: 110, inputs: [],
               outputs: Array.from({ length: 13 }, (_, j) => ({ outpoint: `big${k}:${j}`, value: j })) });
  }
  const L = layout(txs, [100, 129], 1140, 820);
  assert.ok(L.dot > 15 && L.dot < 24, `dot ${L.dot}`);
  assert.ok(L.r > 5, `radius ${L.r}`);  // the fixed layout used 3
  assert.ok(L.width <= 1140 && L.height <= 820, `${L.width}x${L.height}`);
  const big = L.boxes.filter((b) => b.t.txid.startsWith("big"));
  for (let k = 1; k < big.length; k++) assert.ok(big[k].y >= big[k - 1].y + big[k - 1].h, "stacked, not overlapping");
  for (const { t, x, y, h } of L.boxes) {
    for (const o of t.outputs) {
      const [ox, oy] = L.pos[o.outpoint];
      assert.equal(ox, x + L.txw);
      assert.ok(oy > y && oy < y + h, "outputs sit on their transaction's edge");
    }
  }
});

test("a history too tall for the viewport keeps a legible minimum and scrolls", () => {
  const txs = [];
  for (let k = 0; k < 20; k++) {
    txs.push({ txid: `x${k}`, kind: "coinjoin", height: 5, inputs: [],
               outputs: Array.from({ length: 12 }, (_, j) => ({ outpoint: `x${k}:${j}`, value: 1 })) });
  }
  const L = layout(txs, null, 800, 400);
  assert.equal(L.dot, 7);
  assert.ok(L.height > 400);
});

test("tracing follows coins forward through every spending transaction", () => {
  const txs = history(4, 2);
  const { outs, txids } = trace(txs, ["t1:0"]);
  assert.deepEqual([...txids].sort(), ["t2", "t3"]);
  assert.ok(outs.has("t3:1") && outs.has("t1:0"));
  assert.ok(!outs.has("t1:1") && !outs.has("t0:0"), "siblings and ancestors are not downstream");
  assert.deepEqual([...trace(txs, ["t1:1"]).txids], [], "an unspent output goes nowhere");
});

test("a revealed near miss shows the right, the wrong and the missed outputs", () => {
  const v = classifyGuess(["a:0", "b:1", "c:2"], ["a:0", "b:1", "c:5"]);
  assert.deepEqual([...v.right], ["a:0", "b:1"]);
  assert.deepEqual([...v.wrong], ["c:2"]);
  assert.deepEqual([...v.missed], ["c:5"]);
});
