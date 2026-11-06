"""coinjoinctf CLI: stage, setup, play, audit, reveal, demo (narrated, for recordings), serve."""

from __future__ import annotations

import argparse
import collections
import json
import sys
import time
from pathlib import Path
from typing import Any

from coinjoinctf.rpc import node
from coinjoinctf.session import DEFAULT_STATE, Session
from coinjoinctf.stage import StageConfig

B, DIM, G, R, Y, C, X = "\033[1m", "\033[2m", "\033[32m", "\033[31m", "\033[33m", "\033[36m", "\033[0m"


def short(h: str, n: int = 10) -> str:
    return h[:n] + "…" if len(h) > n else h


def shape(j: dict[str, Any]) -> str:
    """The lineage shape the setup proof discloses (minimums over the tips)."""
    return (f"{j['n_tips']} tips in {j['tip_txs']} txs, each >= {j['min_depth']} hops from U0, "
            f"anonymity set >= {j['min_anonymity']}, >= {j['min_foreign_inputs']} outside inputs per hop")  # fmt: skip


class Printer:
    """Narrates events as they happen. Keeps lines short enough for an 100-column recording."""

    def __init__(self) -> None:
        self.kinds: collections.Counter[str] = collections.Counter()
        self.host_hint = 0

    def __call__(self, kind: str, **d: Any) -> None:
        getattr(self, f"on_{kind}", self.default)(kind, d)
        sys.stdout.flush()

    def default(self, kind: str, d: dict[str, Any]) -> None:
        print(f"  {DIM}{kind}{X}")

    def on_stage_start(self, k: str, d: dict[str, Any]) -> None:
        print(f"{B}== Stage: JoinMarket ecosystem on regtest{X}")

    def on_agents(self, k: str, d: dict[str, Any]) -> None:
        bonded = [m for m in d["makers"] if m["bond"]]
        print(
            f"  {len(d['makers'])} makers ({len(bonded)} with fidelity bonds), {d['takers']} random takers, 1 host tumbler"
        )
        for m in bonded[:3]:
            b = m["bond"]
            print(f"  {DIM}{m['nick']}: bond {b['value'] / 1e8:.2f} BTC locked until "
                  f"{time.strftime('%Y-%m', time.gmtime(b['locktime']))}, {m['type']} {m['cjfee']}{X}")  # fmt: skip

    def on_tx(self, k: str, d: dict[str, Any]) -> None:
        self.kinds[d["tx"]["kind"]] += 1

    def on_block(self, k: str, d: dict[str, Any]) -> None:
        parts = ", ".join(f"{n} {kind}" for kind, n in sorted(self.kinds.items()))
        print(f"  block {d['height']}: {'#' * d['txs']:<12} {DIM}{parts}{X}")
        self.kinds.clear()

    def on_stage_done(self, k: str, d: dict[str, Any]) -> None:
        print(f"  {G}history frozen{X}: blocks {d['start_height']}..{d['end_height']}, {d['txs']} txs, "
              f"{d['outputs']} outputs\n  challenge: find every tip descending from U0 = {C}{short(d['u0'], 16)}{X}")  # fmt: skip

    def on_proving(self, k: str, d: dict[str, Any]) -> None:
        mode = "dev mode, fake seal" if d["dev"] else "real STARK"
        print(
            f"{B}== Setup: host commits to the answer and proves it in RISC Zero{X} ({mode}, {d['blocks']} blocks)"
        )

    def on_setup(self, k: str, d: dict[str, Any]) -> None:
        j, m = d["journal"], d["manifest"]
        print(f"  proof: {d['cycles']:,} cycles, {d['seconds']} s, image {short(d['image_id'], 16)}")
        print(
            f"  journal: n_tips={B}{j['n_tips']}{X} com={short(j['com'], 16)} wallet={short(j['wallet_commitment'], 16)}"
        )
        print(f"  proven: U0 was spent; {shape(j)}")
        print(f"  bounty {m['bounty'] / 1e8} BTC, entry fee {m['entry_fee'] / 1e8} BTC, "
              f"{m['n_instances']} garbled circuits per entry, keep {m['n_retained']}")  # fmt: skip

    def on_entry(self, k: str, d: dict[str, Any]) -> None:
        s = d["setup"]
        print(f"{B}== Entry {d['name']}{X}")
        print(f"  {G}✓{X} setup proof verified against own node: blocks {s['start_hash'][:8]}…{s['end_hash'][:8]}, "
              f"{s['n_tips']} tips committed{' (dev)' if s['fake'] else ''}")  # fmt: skip
        print(f"  {DIM}proven: {shape(s)}{X}")

    def on_guess(self, k: str, d: dict[str, Any]) -> None:
        print(f"  guess: {len(d['tips'])} tips -> x = {short(d['x'], 16)}")
        for t in d["tips"]:
            print(f"    {DIM}{short(t.split(':')[0], 16)}:{t.split(':')[1]}{X}")

    def on_offer(self, k: str, d: dict[str, Any]) -> None:
        print(f"  host commits to {d['n']} fresh garbled circuits ({d['and_gates']:,} AND gates, "
              f"{d['table_bytes'] / 1e6:.1f} MB each)")  # fmt: skip

    def on_choose(self, k: str, d: dict[str, Any]) -> None:
        print(f"  participant keeps {d['retained']} (signed), host must open the rest")

    def on_verified(self, k: str, d: dict[str, Any]) -> None:
        print(f"  {G}✓{X} {d['checked']} opened circuits re-garbled honestly "
              f"(cheat chance 1/{round(1 / d['cheat_probability'])})")  # fmt: skip

    def on_funded(self, k: str, d: dict[str, Any]) -> None:
        print(f"  funded {short(d['txid'])}: entry {d['entry_fee'] / 1e8} + bounty {d['bounty'] / 1e8} BTC "
              f"locked in {short(d['contract_address'], 14)}")  # fmt: skip

    def on_asserted(self, k: str, d: dict[str, Any]) -> None:
        bits = "".join(map(str, d["bits"]))
        print(
            f"  asserted {short(d['txid'])} ({d['vsize']} vB): guess bits on-chain via Lamport {DIM}{bits[:48]}…{X}"
        )

    def on_delivered(self, k: str, d: dict[str, Any]) -> None:
        print(f"  delivered {short(d['txid'])} ({d['vsize']} vB): {d['labels']} input labels, script-checked "
              f"against the asserted bits")  # fmt: skip

    def on_evaluated(self, k: str, d: dict[str, Any]) -> None:
        for i in d["instances"]:
            if "error" in i:
                print(f"    circuit {i['instance']}: {R}{i['error']}{X}")
            else:
                print(f"    circuit {i['instance']}: win={i['win']} eq={i['eq']} o1={i['o1']}")
        print(f"  {G + 'WIN' if d['won'] else R + 'no win'}{X}")

    def on_claimed(self, k: str, d: dict[str, Any]) -> None:
        print(f"  {G}{B}claimed {d['value'] / 1e8} BTC{X} with the win label (tx {short(d['txid'])})")

    def on_settled(self, k: str, d: dict[str, Any]) -> None:
        print(f"  host settled {d['value'] / 1e8} BTC after the CSV delay (tx {short(d['txid'])})")

    def on_timeout(self, k: str, d: dict[str, Any]) -> None:
        print(
            f"  host stalled: participant reclaimed {d['value'] / 1e8} BTC via timeout (tx {short(d['txid'])})"
        )

    def on_audit(self, k: str, d: dict[str, Any]) -> None:
        print(f"{B}== Public audit of {d['name']}{X}: {d['verdict']}")
        print(f"  {DIM}choice signature, {d['opened_checked']} opened circuits, on-chain guess "
              f"{short(d['guess'], 16)}, labels re-evaluated, setup proof re-verified{X}")  # fmt: skip

    def on_reveal(self, k: str, d: dict[str, Any]) -> None:
        print(f"{B}== Reveal{X} (optional, after the game): {len(d['host_txids'])} host transactions")
        for t in d["tips"]:
            print(f"  tip {C}{t}{X}")


def _session(a: argparse.Namespace, emit: Any = None) -> Session:
    return Session(node(), Path(a.state), emit or Printer(), dev_proof=a.dev)


def cmd_demo(a: argparse.Namespace) -> None:
    """The whole story for a recording: stage, setup, a near miss + audit, a win + claim, reveal."""
    s = _session(a)
    pause = a.pause
    if a.fresh or s.stage is None:
        s.run_stage(StageConfig(n_makers=a.makers, n_takers=a.takers))
        time.sleep(pause)
    if a.fresh or s.manifest is None:
        s.setup()
        time.sleep(pause)
    guesses = s.demo_guesses()
    name = s.play(guesses["near_miss"])["name"]
    time.sleep(pause)
    s.audit(name)
    time.sleep(pause)
    s.play(guesses["correct"])
    time.sleep(pause)
    s.reveal()


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="coinjoinctf", description=__doc__)
    p.add_argument("--state", default=str(DEFAULT_STATE), help="state directory")
    p.add_argument("--dev", action="store_true", help="RISC Zero dev mode (fake proofs, fast)")
    sub = p.add_subparsers(dest="cmd", required=True)
    st = sub.add_parser("stage", help="run the JoinMarket ecosystem and the host tumbler")
    st.add_argument("--makers", type=int, default=12)
    st.add_argument("--takers", type=int, default=4)
    sub.add_parser("setup", help="host: commit to the answer and prove the setup statement")
    pl = sub.add_parser("play", help="participant: enter with a guess")
    pl.add_argument("tips", nargs="*", help="txid:vout of every tip")
    pl.add_argument("--demo-guess", choices=["correct", "near_miss"], help="let the host pick a guess")
    pl.add_argument("--stall", action="store_true", help="simulate a host that never delivers labels")
    au = sub.add_parser("audit", help="anyone: audit a finished entry")
    au.add_argument("name")
    sub.add_parser("reveal", help="host: optional disclosure after the game")
    de = sub.add_parser("demo", help="narrated end-to-end run")
    de.add_argument("--fresh", action="store_true", help="rerun stage and setup even if state exists")
    de.add_argument("--pause", type=float, default=0.0)
    de.add_argument("--makers", type=int, default=12)
    de.add_argument("--takers", type=int, default=4)
    sv = sub.add_parser("serve", help="web demo")
    sv.add_argument("--port", type=int, default=8000)
    a = p.parse_args(argv)

    if a.cmd == "stage":
        _session(a).run_stage(StageConfig(n_makers=a.makers, n_takers=a.takers))
    elif a.cmd == "setup":
        _session(a).setup()
    elif a.cmd == "play":
        s = _session(a)
        tips = s.demo_guesses()[a.demo_guess] if a.demo_guess else a.tips
        if not tips:
            p.error("give tips or --demo-guess")
        print(json.dumps({k: v for k, v in s.play(tips, stall=a.stall).items() if k != "instances"}))
    elif a.cmd == "audit":
        _session(a).audit(a.name)
    elif a.cmd == "reveal":
        _session(a).reveal()
    elif a.cmd == "demo":
        cmd_demo(a)
    elif a.cmd == "serve":
        from coinjoinctf.web import serve

        serve(Path(a.state), a.port, dev=a.dev)
