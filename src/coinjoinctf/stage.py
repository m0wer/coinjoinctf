"""Agent-based JoinMarket stage on regtest: makers with fidelity bonds, autonomous takers, a tumbler.

Every transaction is real, fully signed and mined. Each agent is a JoinMarket-style wallet with 5
mixdepths. A coinjoin of amount A gives every participant one equal output A (makers: to the next
mixdepth; taker: to its destination) and a change output in the source mixdepth. Makers are picked
like JoinMarket's fidelity-bond-weighted order choice. The tumbler (the host's wallet) runs a
simplified JoinMarket tumbler schedule with random block delays.
"""

from __future__ import annotations

import hashlib
import math
import os
import random
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from bitcointx.core.script import (
    OP_CHECKLOCKTIMEVERIFY,
    OP_CHECKSIG,
    OP_DROP,
    CScript,
)
from bitcointx.wallet import CCoinKey, P2WSHCoinAddress
from pydantic import BaseModel

from coinjoinctf.chain import Coin, address, broadcast, fund, new_tx, p2wpkh, sign_p2wpkh
from coinjoinctf.rpc import RPC, mine

MIXDEPTHS = 5
FEERATE = 2  # sat/vB
DUST = 2_730
SECP_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
YEAR = 60 * 60 * 24 * 365.2425


def wallet_key(seed: bytes, index: int) -> CCoinKey | None:
    """Owned-key derivation shared with the ZK guest: SHA256(tag || seed || index_le32)."""
    sk = hashlib.sha256(b"coinjoinctf/wallet/v1" + seed + index.to_bytes(4, "little")).digest()
    if not 0 < int.from_bytes(sk, "big") < SECP_N:
        return None  # skipped index; probability ~2^-128
    return CCoinKey.from_secret_bytes(sk)


@dataclass
class Utxo:
    coin: Coin
    mixdepth: int
    key: CCoinKey


@dataclass
class Wallet:
    name: str
    seed: bytes
    next_index: int = 0
    utxos: list[Utxo] = field(default_factory=list)

    def new_output(self) -> tuple[CCoinKey, bytes]:
        while True:
            key = wallet_key(self.seed, self.next_index)
            self.next_index += 1
            if key is not None:
                return key, bytes(p2wpkh(key))

    def balance(self, md: int, locked: set[str] | None = None) -> int:
        return sum(u.coin.value for u in self.spendable(md, locked))

    def spendable(self, md: int, locked: set[str] | None = None) -> list[Utxo]:
        locked = locked or set()
        return [u for u in self.utxos if u.mixdepth == md and u.coin.outpoint not in locked]

    def select(self, md: int, target: int, locked: set[str]) -> list[Utxo] | None:
        """Largest-first selection within one mixdepth (JoinMarket never mixes mixdepths)."""
        chosen, total = [], 0
        for u in sorted(self.spendable(md, locked), key=lambda u: -u.coin.value):
            chosen.append(u)
            total += u.coin.value
            if total >= target:
                return chosen
        return None


@dataclass
class Bond:
    """Timelocked P2WSH fidelity bond. locktime is a unix timestamp (first of a month), as in JM."""

    coin: Coin
    locktime: int
    confirmation_time: int

    def value(self, now: float, rate: float = 0.015, exponent: float = 1.3) -> float:
        """JoinMarket calculate_timelocked_fidelity_bond_value (interest 1.5%, exponent 1.3)."""
        t_lock = (self.locktime - self.confirmation_time) / YEAR
        a = max(
            0.0,
            min(1.0, math.exp(rate * t_lock) - 1)
            - min(1.0, math.exp(rate * max(0.0, (now - self.locktime) / YEAR)) - 1),
        )
        return float((self.coin.value * a) ** exponent)


def bond_script(key: CCoinKey, locktime: int) -> CScript:
    return CScript([locktime, OP_CHECKLOCKTIMEVERIFY, OP_DROP, key.pub, OP_CHECKSIG])


def bond_spk(key: CCoinKey, locktime: int) -> bytes:
    return bytes(P2WSHCoinAddress.from_redeemScript(bond_script(key, locktime)).to_scriptPubKey())


@dataclass
class Maker:
    wallet: Wallet
    bond: Bond | None
    reloffer: bool
    cjfee: float  # relative fraction (reloffer) or absolute sats (absoffer)
    minsize: int

    def fee(self, amount: int) -> int:
        return round(amount * self.cjfee) if self.reloffer else int(self.cjfee)

    def mixdepth_for(self, amount: int, locked: set[str]) -> int | None:
        """yg-basic: serve from the mixdepth with the largest balance that covers the amount."""
        best = max(range(MIXDEPTHS), key=lambda md: self.wallet.balance(md, locked))
        return best if self.wallet.balance(best, locked) >= amount else None


def choose_makers(
    rng: random.Random, makers: list[Maker], amount: int, n: int, now: float, locked: set[str]
) -> list[Maker]:
    """JoinMarket fidelity_bond_weighted_order_choose with bondless_makers_allowance = 0.125."""
    pool = [m for m in makers if m.minsize <= amount and m.mixdepth_for(amount, locked) is not None]
    chosen: list[Maker] = []
    while pool and len(chosen) < n:
        weights = [m.bond.value(now) if m.bond else 0.0 for m in pool]
        if rng.random() < 0.125 or sum(weights) == 0:
            pick = rng.choice(pool)
        else:
            pick = rng.choices(pool, weights=weights)[0]
        chosen.append(pick)
        pool.remove(pick)
    return chosen


def _vsize(n_in: int, n_out: int) -> int:
    return 11 + 68 * n_in + 31 * n_out


@dataclass
class TxRecord:
    txid: str
    kind: str  # deposit | coinjoin | payment
    inputs: list[dict[str, Any]]
    outputs: list[dict[str, Any]]
    owners_in: list[str]  # private truth, never shown before the reveal
    owners_out: list[str]
    meta: dict[str, Any] = field(default_factory=dict)
    height: int = 0  # set once mined

    def public(self) -> dict[str, Any]:
        return {"txid": self.txid, "kind": self.kind, "height": self.height,
                "inputs": self.inputs, "outputs": self.outputs, "meta": self.meta}  # fmt: skip


def build_and_send(
    rpc: RPC, rng: random.Random, spends: list[tuple[Utxo, Wallet]],
    outs: list[tuple[int, Wallet, int]], kind: str, meta: dict[str, Any],
) -> TxRecord:  # fmt: skip
    """Shuffle, sign every input with its owner's key, broadcast, and update wallets."""
    rng.shuffle(spends)
    created = []
    for value, wallet, md in outs:
        key, spk = wallet.new_output()
        created.append((value, wallet, md, key, spk))
    rng.shuffle(created)
    tx = new_tx([u.coin for u, _ in spends], [(v, spk) for v, _, _, _, spk in created], sequence=0xFFFFFFFE)
    for i, (u, _) in enumerate(spends):
        sign_p2wpkh(tx, i, u.coin, u.key)
    txid = broadcast(rpc, tx)
    for u, w in spends:
        w.utxos.remove(u)
    outputs = []
    for n, (value, wallet, md, key, spk) in enumerate(created):
        coin = Coin(txid, n, value, spk)
        wallet.utxos.append(Utxo(coin, md, key))
        outputs.append({"outpoint": coin.outpoint, "value": value, "address": address(CScript(spk))})
    inputs = [{"outpoint": u.coin.outpoint, "value": u.coin.value} for u, _ in spends]
    return TxRecord(txid, kind, inputs, outputs,
                    [w.name for _, w in spends], [w.name for _, w, _, _, _ in created], meta)  # fmt: skip


def coinjoin(
    rpc: RPC, rng: random.Random, taker: Wallet, md: int, fraction: float | None,
    dest: tuple[Wallet, int], makers: list[Maker], locked: set[str],
) -> TxRecord | None:  # fmt: skip
    """fraction=None sweeps the mixdepth (no taker change), like JoinMarket sweeps."""
    balance = taker.balance(md, locked)
    rel = sum(m.cjfee for m in makers if m.reloffer)
    absf = sum(int(m.cjfee) for m in makers if not m.reloffer)
    if fraction is None:
        t_utxos = taker.spendable(md, locked)
        n_in = len(t_utxos) + 2 * len(makers)
        amount = int((balance - absf - _vsize(n_in, 1 + 2 * len(makers)) * FEERATE) / (1 + rel))
    else:
        amount = int(balance * fraction)
        sel = taker.select(md, amount, locked)
        if sel is None:
            return None
        t_utxos = sel
    parts = []
    for m in makers:
        mmd = m.mixdepth_for(amount, locked)
        sel = m.wallet.select(mmd, amount, locked) if mmd is not None else None
        if sel is None:
            return None
        parts.append((m, mmd, sel))
    n_in = len(t_utxos) + sum(len(s) for _, _, s in parts)
    n_out = 1 + 2 * len(makers) + (0 if fraction is None else 1)
    mining = _vsize(n_in, n_out) * FEERATE
    cjfees = sum(m.fee(amount) for m in makers)
    t_in = sum(u.coin.value for u in t_utxos)
    if fraction is None:  # recompute with the real input count
        amount = int((t_in - absf - mining) / (1 + rel))
        cjfees = sum(m.fee(amount) for m in makers)
    t_change = t_in - amount - cjfees - mining
    if amount < 100_000 or t_change < 0:
        return None
    spends = [(u, taker) for u in t_utxos]
    outs: list[tuple[int, Wallet, int]] = [(amount, dest[0], dest[1])]
    if fraction is not None and t_change > DUST:
        outs.append((t_change, taker, md))
    for m, mmd, sel in parts:
        spends += [(u, m.wallet) for u in sel]
        outs.append((amount, m.wallet, (mmd + 1) % MIXDEPTHS))
        change = sum(u.coin.value for u in sel) - amount + m.fee(amount)
        if change > DUST:
            outs.append((change, m.wallet, mmd))
    for u, _ in spends:
        locked.add(u.coin.outpoint)
    rec = build_and_send(rpc, rng, spends, outs, "coinjoin",
                         {"amount": amount, "makers": len(makers), "sweep": fraction is None})  # fmt: skip
    for o in rec.outputs:
        locked.add(o["outpoint"])  # unconfirmed: nobody spends it this block
    return rec


@dataclass(frozen=True)
class Step:
    """One tumbler coinjoin. fraction=None sweeps the mixdepth; final steps pay a destination."""

    mixdepth: int
    fraction: float | None
    n_makers: int
    wait: int  # blocks to wait before attempting this step
    final: bool


def tumbler_schedule(rng: random.Random, final_md: int = 3, destinations: int = 3) -> list[Step]:
    """Simplified JoinMarket tumbler: per mixdepth some partial coinjoins then a sweep to the next
    mixdepth; the last mixdepth splits into destination addresses (the challenge tips)."""
    steps: list[Step] = []
    for md in range(final_md):
        k = rng.randint(1, 3)
        for i in range(k):
            frac = None if i == k - 1 else round(rng.uniform(0.15, 0.5), 3)
            steps.append(Step(md, frac, rng.randint(3, 6), rng.randint(1, 4), False))
    for i in range(destinations):
        frac = None if i == destinations - 1 else round(rng.uniform(0.6, 1.4) / (destinations - i), 3)
        steps.append(Step(final_md, frac, rng.randint(3, 6), rng.randint(1, 4), True))
    return steps


def taker_action(
    rpc: RPC, rng: random.Random, taker: Wallet, sink: Wallet, makers: list[Maker], now: float,
    locked: set[str],
) -> TxRecord | None:  # fmt: skip
    """A random JoinMarket taker: sendpayment to an outside address or to its own next mixdepth."""
    mds = [md for md in range(MIXDEPTHS) if taker.balance(md, locked) > 1_000_000]
    if not mds:
        return None
    md = rng.choice(mds)
    fraction = None if rng.random() < 0.3 else round(rng.uniform(0.1, 0.8), 3)
    dest = (sink, -1) if rng.random() < 0.35 else (taker, (md + 1) % MIXDEPTHS)
    estimate = int(taker.balance(md, locked) * (fraction or 1.0))
    chosen = choose_makers(rng, makers, estimate, rng.randint(3, 6), now, locked)
    if len(chosen) < 3:
        return None
    return coinjoin(rpc, rng, taker, md, fraction, dest, chosen, locked)


def maker_payment(
    rpc: RPC, rng: random.Random, maker: Maker, sink: Wallet, locked: set[str]
) -> TxRecord | None:
    """Makers occasionally spend: a plain payment with change back to the same mixdepth."""
    w = maker.wallet
    mds = [md for md in range(MIXDEPTHS) if w.balance(md, locked) > 2_000_000]
    if not mds:
        return None
    md = rng.choice(mds)
    amount = int(w.balance(md, locked) * rng.uniform(0.05, 0.4))
    sel = w.select(md, amount, locked)
    if sel is None:
        return None
    change = sum(u.coin.value for u in sel) - amount - _vsize(len(sel), 2) * FEERATE
    outs = [(amount, sink, -1)] + ([(change, w, md)] if change > DUST else [])
    for u in sel:
        locked.add(u.coin.outpoint)
    rec = build_and_send(rpc, rng, [(u, w) for u in sel], outs, "payment", {"amount": amount})
    locked.update(o["outpoint"] for o in rec.outputs)
    return rec


Event = Callable[[str, dict[str, Any]], None]


@dataclass
class StageConfig:
    n_makers: int = 12
    n_takers: int = 4
    bonded_fraction: float = 0.7
    taker_p: float = 0.35  # per taker per block
    payment_p: float = 0.03  # per maker per block
    warmup_ticks: int = 2
    tail_ticks: int = 2
    u0_value: int = 100_000_000
    max_ticks: int = 150
    seed: int | None = None  # behavior RNG for tests only; wallet seeds always come from the OS


class StageResult(BaseModel):
    """Host-private record of a stage run; ``public()`` is what everyone gets."""

    u0: str
    start_height: int
    end_height: int
    start_hash: str
    end_hash: str
    txs: list[dict[str, Any]]
    makers: list[dict[str, Any]]  # orderbook view: offers and fidelity bonds
    # private:
    tips: list[str]
    tumbler_seed: str
    key_limit: int
    owners: dict[str, str]  # outpoint -> agent
    host_txids: list[str]

    def public(self) -> dict[str, Any]:
        return self.model_dump(exclude={"tips", "tumbler_seed", "owners", "host_txids"})

    def wallet_commitment(self) -> str:
        return hashlib.sha256(bytes.fromhex(self.tumbler_seed)).hexdigest()


def _month_start(months_ahead: int) -> int:
    now = datetime.now(UTC)
    y, m = divmod(now.month - 1 + months_ahead, 12)
    return int(datetime(now.year + y, m + 1, 1, tzinfo=UTC).timestamp())


def chain_record(rpc: RPC, txid: str, kind: str, owner_of: Callable[[str], str]) -> TxRecord:
    """Build a record for a transaction made outside the agents (e.g. the exchange withdrawal)."""
    raw = rpc.getrawtransaction(txid, True)
    inputs = []
    for i in raw["vin"]:
        prev = rpc.getrawtransaction(i["txid"], True)["vout"][i["vout"]]
        inputs.append({"outpoint": f"{i['txid']}:{i['vout']}", "value": round(prev["value"] * 1e8)})
    outputs = [
        {
            "outpoint": f"{txid}:{o['n']}",
            "value": round(o["value"] * 1e8),
            "address": o["scriptPubKey"].get("address", ""),
        }
        for o in raw["vout"]
    ]
    return TxRecord(
        txid, kind, inputs, outputs, ["outside"] * len(inputs), [owner_of(o["outpoint"]) for o in outputs]
    )


class Stage:
    """Runs the ecosystem block by block. The host's tumbler is just one more taker in it."""

    def __init__(self, rpc: RPC, cfg: StageConfig | None = None, on_event: Event | None = None) -> None:
        self.rpc, self.cfg = rpc, cfg or StageConfig()
        self.rng: random.Random = (
            random.Random(self.cfg.seed) if self.cfg.seed is not None else random.SystemRandom()
        )
        self.emit: Event = on_event or (lambda kind, data: None)
        self.makers: list[Maker] = []
        self.takers: list[Wallet] = []
        self.sink = Wallet("outside", os.urandom(32))
        self.tumbler = Wallet("host", os.urandom(32))
        self.schedule = tumbler_schedule(self.rng)
        self.pos, self.wait = 0, self.schedule[0].wait
        self.txs: list[TxRecord] = []
        self.host_txids: list[str] = []
        self.u0: Utxo | None = None
        self.start_height = 0

    @property
    def tumbler_done(self) -> bool:
        return self.pos >= len(self.schedule)

    def setup(self) -> None:
        rng, cfg = self.rng, self.cfg
        coins: list[tuple[int, bytes, Wallet, int, CCoinKey]] = []
        bonds: list[tuple[int, bytes, Maker, int]] = []
        for i in range(cfg.n_makers):
            w = Wallet(f"maker{i + 1}", os.urandom(32))
            for _ in range(rng.randint(3, 6)):
                key, spk = w.new_output()
                coins.append((rng.randint(30, 400) * 1_000_000, spk, w, rng.randrange(MIXDEPTHS), key))
            rel = rng.random() < 0.7
            fee = round(rng.uniform(0.00002, 0.0003), 6) if rel else float(rng.randint(250, 3000))
            maker = Maker(w, None, rel, fee, rng.randint(1, 10) * 100_000)
            self.makers.append(maker)
            if rng.random() < cfg.bonded_fraction:
                key, _ = w.new_output()
                locktime = _month_start(rng.randint(6, 60))
                bonds.append((rng.randint(5, 80) * 10_000_000, bond_spk(key, locktime), maker, locktime))
        for i in range(cfg.n_takers):
            w = Wallet(f"taker{i + 1}", os.urandom(32))
            for _ in range(rng.randint(2, 4)):
                key, spk = w.new_output()
                coins.append((rng.randint(50, 300) * 1_000_000, spk, w, rng.randrange(MIXDEPTHS), key))
            self.takers.append(w)
        _, created = fund(self.rpc, [(v, s) for v, s, *_ in coins] + [(v, s) for v, s, *_ in bonds])
        conf_time = self.rpc.getblock(self.rpc.getbestblockhash())["time"]
        for (_, _, w, md, key), coin in zip(coins, created[: len(coins)], strict=True):
            w.utxos.append(Utxo(coin, md, key))
        for (_, _, maker, lt), coin in zip(bonds, created[len(coins) :], strict=True):
            maker.bond = Bond(coin, lt, conf_time)
        self.emit("agents", {"makers": self.orderbook(), "takers": len(self.takers)})
        for _ in range(cfg.warmup_ticks):
            self.tick(tumbler=False)
        # U0: the host withdraws 1 BTC from an "exchange" into tumbler mixdepth 0.
        key, spk = self.tumbler.new_output()
        txid, (coin,) = fund(self.rpc, [(cfg.u0_value, spk)], confirm=False)
        self.u0 = Utxo(coin, 0, key)
        self.tumbler.utxos.append(self.u0)
        self.host_txids.append(txid)
        dep = chain_record(self.rpc, txid, "deposit", lambda op: "host" if op == coin.outpoint else "outside")
        self.tick([dep], tumbler=False, locked={coin.outpoint})
        self.start_height = dep.height

    def orderbook(self) -> list[dict[str, Any]]:
        book = []
        for m in self.makers:
            bond = None
            if m.bond:
                bond = {
                    "outpoint": m.bond.coin.outpoint,
                    "value": m.bond.coin.value,
                    "locktime": m.bond.locktime,
                }
            book.append({"nick": m.wallet.name, "type": "reloffer" if m.reloffer else "absoffer",
                         "cjfee": m.cjfee, "minsize": m.minsize, "bond": bond})  # fmt: skip
        return book

    def _tumbler_step(self, locked: set[str], now: float) -> TxRecord | None:
        self.wait -= 1
        if self.wait > 0:
            return None
        step = self.schedule[self.pos]
        estimate = int(self.tumbler.balance(step.mixdepth, locked) * (step.fraction or 1.0))
        makers = choose_makers(self.rng, self.makers, estimate, step.n_makers, now, locked)
        if len(makers) < 3:
            return None  # not enough liquidity this block; retry next block
        dest = (self.tumbler, -1 if step.final else step.mixdepth + 1)
        rec = coinjoin(self.rpc, self.rng, self.tumbler, step.mixdepth, step.fraction, dest, makers, locked)
        if rec is None:
            return None
        self.host_txids.append(rec.txid)
        self.pos += 1
        if not self.tumbler_done:
            self.wait = self.schedule[self.pos].wait
        return rec

    def tick(
        self, recs: list[TxRecord] | None = None, tumbler: bool = True, locked: set[str] | None = None
    ) -> list[TxRecord]:
        """One block: every agent may act (in random order), then the block is mined."""
        recs, locked, now = list(recs or []), set(locked or ()), time.time()
        actors: list[tuple[str, Any]] = [("host", None)] if tumbler and not self.tumbler_done else []
        actors += [("taker", t) for t in self.takers if self.rng.random() < self.cfg.taker_p]
        actors += [("maker", m) for m in self.makers if self.rng.random() < self.cfg.payment_p]
        self.rng.shuffle(actors)
        for kind, agent in actors:
            if kind == "host":
                rec = self._tumbler_step(locked, now)
            elif kind == "taker":
                rec = taker_action(self.rpc, self.rng, agent, self.sink, self.makers, now, locked)
            else:
                rec = maker_payment(self.rpc, self.rng, agent, self.sink, locked)
            if rec is not None:
                recs.append(rec)
        mine(self.rpc)
        height = self.rpc.getblockcount()
        for r in recs:
            r.height = height
            self.txs.append(r)
            self.emit("tx", r.public())
        self.emit("block", {"height": height, "txs": len(recs)})
        return recs

    def run(self) -> StageResult:
        self.setup()
        for _ in range(self.cfg.max_ticks):
            if self.tumbler_done:
                break
            self.tick()
        else:
            raise RuntimeError("tumbler schedule did not complete; raise max_ticks or add liquidity")
        for _ in range(self.cfg.tail_ticks):
            self.tick(tumbler=False)
        return self.result()

    def result(self) -> StageResult:
        assert self.u0 is not None
        end = self.rpc.getblockcount()
        in_range = [r for r in self.txs if r.height >= self.start_height]
        owners = {
            o["outpoint"]: who for r in in_range for o, who in zip(r.outputs, r.owners_out, strict=True)
        }
        return StageResult(
            u0=self.u0.coin.outpoint,
            start_height=self.start_height,
            end_height=end,
            start_hash=self.rpc.getblockhash(self.start_height),
            end_hash=self.rpc.getblockhash(end),
            txs=[r.public() for r in in_range],
            makers=self.orderbook(),
            tips=sorted(u.coin.outpoint for u in self.tumbler.utxos),
            tumbler_seed=self.tumbler.seed.hex(),
            key_limit=-(-self.tumbler.next_index // 16) * 16,  # padded: hides the exact address count
            owners=owners,
            host_txids=self.host_txids,
        )


def owned_spks(seed: bytes, key_limit: int) -> set[bytes]:
    return {bytes(p2wpkh(k)) for i in range(key_limit) if (k := wallet_key(seed, i)) is not None}


def owned_tips(rpc: RPC, seed: bytes, key_limit: int, u0: str, start: int, end: int) -> list[str]:
    """Reference for the ZK statement: scan blocks [start, end] in order. The lineage is U0 (which
    must be owned and created in range) plus every owned output of a transaction spending a lineage
    output. Tips are the lineage outputs still unspent at ``end``."""
    owned = owned_spks(seed, key_limit)
    lineage: set[str] = set()
    spent: set[str] = set()
    for h in range(start, end + 1):
        for tx in rpc.getblock(rpc.getblockhash(h), 2)["tx"]:
            hit = {f"{i['txid']}:{i['vout']}" for i in tx["vin"] if "txid" in i} & lineage
            spent |= hit
            for o in tx["vout"]:
                op, spk = f"{tx['txid']}:{o['n']}", bytes.fromhex(o["scriptPubKey"]["hex"])
                if op == u0:
                    if spk not in owned:
                        raise ValueError("U0 is not owned by the committed wallet")
                    lineage.add(op)
                elif hit and spk in owned:
                    lineage.add(op)
    if u0 not in lineage:
        raise ValueError("U0 is not created in the committed block range")
    return sorted(lineage - spent)
