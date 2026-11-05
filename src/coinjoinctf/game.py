"""Host and participant roles. They only exchange the explicit values passed between methods.

Trust boundary: the participant never receives seeds of retained instances, the free-XOR delta,
or the host's plaintext inputs; the host never learns the guess before it is on-chain. The prize
is the host's stake inside the entry contract, released by the label of the circuit output win=1.
"""

from __future__ import annotations

import hashlib
import os
import secrets
from collections.abc import Callable
from dataclasses import dataclass, field
from math import comb
from typing import Any

from bitcointx.core import CMutableTransaction
from bitcointx.core.key import XOnlyPubKey
from bitcointx.core.script import CScript
from bitcointx.wallet import CCoinKey
from pydantic import BaseModel, ConfigDict

from coinjoinctf import contract as ct
from coinjoinctf.chain import (
    FEERATE,
    Coin,
    address,
    broadcast,
    fund,
    new_tx,
    p2tr_key,
    set_witness,
    sign_p2tr_key,
    vsize,
)
from coinjoinctf.circuit import (
    HOST_WIRES,
    OUT_EQ,
    OUT_O1,
    OUT_WIN,
    X_BITS,
    X_WIRES,
    Circuit,
    answer_commitment,
    bytes_to_bits,
    game_circuit,
)
from coinjoinctf.garble import EvaluationError, GarbledPublic, GarbledSecret, evaluate, garble, verify_opened
from coinjoinctf.rpc import RPC, mine

Emit = Callable[..., None]
SetupVerifier = Callable[["GameManifest"], dict[str, Any]]


def answer_hash(outpoints: list[str]) -> bytes:
    """Canonical tip-set encoding: SHA256 of sorted, newline-joined 'txid:vout', first 128 bits."""
    return hashlib.sha256("\n".join(sorted(set(outpoints))).encode()).digest()[: X_BITS // 8]


class History(BaseModel):
    """The frozen, public block range the challenge is about, and the ownership definition."""

    model_config = ConfigDict(frozen=True)
    u0: str
    start_height: int
    end_height: int
    start_hash: str
    end_hash: str
    wallet_commitment: str  # SHA256(wallet seed); owned = P2WPKH of a seed key with index < key_limit
    key_limit: int


class GameManifest(BaseModel):
    """Published once per game, before anyone plays."""

    model_config = ConfigDict(frozen=True)
    history: History
    n_tips: int
    com: str
    n_instances: int
    n_retained: int
    entry_fee: int
    bounty: int
    abort_csv: int
    timeout_csv: int
    settle_csv: int
    circuit_fingerprint: str
    proof: str | None = None  # setup proof receipt (path), verified by every participant

    @property
    def cheat_probability(self) -> float:
        return 1 / comb(self.n_instances, self.n_retained)


@dataclass
class EntryState:
    seeds: list[bytes] = field(default_factory=list)
    garbled: list[GarbledSecret] = field(default_factory=list)
    retained: list[int] = field(default_factory=list)
    terms: ct.ContractTerms | None = None
    deliver_tx: CMutableTransaction | None = None
    deliver_presig: bytes = b""
    asserted_coin: Coin | None = None


class Host:
    def __init__(
        self,
        rpc: RPC,
        history: History,
        tips: list[str],
        *,
        n_instances: int = 20,
        n_retained: int = 3,
        entry_fee: int = 100_000,
        bounty: int = 10_000_000,
        abort_csv: int = 6,
        timeout_csv: int = 6,
        settle_csv: int = 6,
    ) -> None:
        self.rpc, self.history = rpc, history
        self.tips = sorted(set(tips))
        self.y = answer_hash(self.tips)
        self.r = os.urandom(32)
        self.com = answer_commitment(self.y, self.r)
        self.circuit: Circuit = game_circuit(self.com)
        self.key = CCoinKey.from_secret_bytes(os.urandom(32))
        self.params: dict[str, int] = dict(
            n_instances=n_instances, n_retained=n_retained, entry_fee=entry_fee, bounty=bounty,
            abort_csv=abort_csv, timeout_csv=timeout_csv, settle_csv=settle_csv,
        )  # fmt: skip
        self.entries: dict[str, EntryState] = {}

    @property
    def pk(self) -> bytes:
        return bytes(self.key.xonly_pub)

    def stake_coin(self, amount: int) -> Coin:
        """This party's own funds for the entry (a regtest faucet stands in for its wallet)."""
        _, (coin,) = fund(self.rpc, [(amount, bytes(p2tr_key(self.key)))], confirm=False)
        return coin

    def sign_funding(self, tx: CMutableTransaction, idx: int, spent: list[Coin]) -> None:
        sign_p2tr_key(tx, idx, spent, self.key)

    def manifest(self, proof: str | None) -> GameManifest:
        return GameManifest(
            history=self.history, n_tips=len(self.tips), com=self.com.hex(),
            circuit_fingerprint=self.circuit.fingerprint(), proof=proof, **self.params,
        )  # fmt: skip

    # 1. Commit to N fresh garbled instances for this entry (nothing here depends on the guess).
    def offer(self, entry: str) -> list[GarbledPublic]:
        st = self.entries[entry] = EntryState()
        st.seeds = [os.urandom(32) for _ in range(self.params["n_instances"])]
        st.garbled = [garble(self.circuit, s) for s in st.seeds]
        return [g.public for g in st.garbled]

    # 2. Open every instance not retained; hand over the host-input labels of retained ones.
    def open(self, entry: str, retained: list[int]) -> tuple[dict[int, bytes], list[list[bytes]]]:
        st = self.entries[entry]
        if len(set(retained)) != self.params["n_retained"]:
            raise ValueError("wrong number of retained instances")
        st.retained = sorted(retained)
        opened = {i: s for i, s in enumerate(st.seeds) if i not in st.retained}
        bits = bytes_to_bits(self.y + self.r)
        labels = [
            [st.garbled[j].input_label(w, bits[n]) for n, w in enumerate(HOST_WIRES)] for j in st.retained
        ]
        return opened, labels

    # 3. Check the participant's terms and presignature, then presign the assert transaction.
    def accept_terms(
        self, entry: str, terms: ct.ContractTerms, assert_tx: CMutableTransaction, contract_coin: Coin,
        deliver_tx: CMutableTransaction, deliver_presig: bytes,
    ) -> bytes:  # fmt: skip
        st = self.entries[entry]
        pubs = [st.garbled[j].public for j in st.retained]
        if terms.host_pk != self.pk or terms.label_hashes != [p.x_label_hashes for p in pubs]:
            raise ValueError("terms do not commit to the retained instances")
        if terms.win_hashes != [p.output_label_hashes[OUT_WIN][1] for p in pubs]:
            raise ValueError("win hashlocks do not match the retained instances")
        p = self.params
        if (terms.abort_csv, terms.timeout_csv, terms.settle_csv) != (
            p["abort_csv"], p["timeout_csv"], p["settle_csv"],
        ):  # fmt: skip
            raise ValueError("timelocks differ from the manifest")
        asserted = Coin(_txid(assert_tx), 0, assert_tx.vout[0].nValue, ct.tree_spk(terms.asserted_tree()))
        if bytes(assert_tx.vout[0].scriptPubKey) != asserted.spk or len(assert_tx.vout) != 1:
            raise ValueError("assert transaction must pay the agreed asserted output")
        if bytes(deliver_tx.vout[0].scriptPubKey) != ct.tree_spk(terms.delivered_tree()):
            raise ValueError("deliver transaction must pay the agreed delivered output")
        d_script, _ = ct.leaf(terms.asserted_tree(), "deliver")
        sh = d_script.sighash_schnorr(deliver_tx, 0, [asserted.txout()])
        if not XOnlyPubKey(terms.part_pk).verify_schnorr(sh, deliver_presig):
            raise ValueError("invalid participant presignature on the deliver transaction")
        st.terms, st.deliver_tx, st.deliver_presig, st.asserted_coin = (
            terms, deliver_tx, deliver_presig, asserted,
        )  # fmt: skip
        a_script, _ = ct.leaf(terms.contract_tree(), "assert")
        return self.key.sign_schnorr_no_tweak(a_script.sighash_schnorr(assert_tx, 0, [contract_coin.txout()]))

    # 4. After the guess is on-chain, deliver x-labels for exactly the committed bits.
    def deliver(self, entry: str, assert_txid: str) -> tuple[str, list[int]]:
        st = self.entries[entry]
        assert st.terms and st.deliver_tx and st.asserted_coin
        items = _witness(self.rpc, assert_txid)
        preimages = ct.parse_assert_witness(items, X_BITS)
        bits = ct.decode_bits(st.terms.lamport, preimages)
        labels = [[st.garbled[j].input_label(w, bits[n]) for n, w in enumerate(X_WIRES)] for j in st.retained]
        script, cb = ct.leaf(st.terms.asserted_tree(), "deliver")
        tx = st.deliver_tx
        sig = self.key.sign_schnorr_no_tweak(script.sighash_schnorr(tx, 0, [st.asserted_coin.txout()]))
        set_witness(tx, 0, ct.deliver_witness(preimages, labels, st.deliver_presig, sig, script, cb))
        return broadcast(self.rpc, tx), bits

    # 5. If no winning label shows up before settle_csv, the stake goes to the host.
    def settle(self, entry: str, deliver_txid: str) -> str:
        st = self.entries[entry]
        assert st.terms
        coin = _coin(self.rpc, deliver_txid)
        script, cb = ct.leaf(st.terms.delivered_tree(), "settle")
        tx = new_tx([coin], [(coin.value - 300, bytes(p2tr_key(self.key)))], sequence=st.terms.settle_csv)
        sig = self.key.sign_schnorr_no_tweak(script.sighash_schnorr(tx, 0, [coin.txout()]))
        set_witness(tx, 0, [sig, bytes(script), cb])
        return broadcast(self.rpc, tx)

    def reveal(self) -> dict[str, Any]:
        """Optional post-game disclosure. The contract never depends on it."""
        return {"tips": self.tips, "y": self.y.hex(), "r": self.r.hex()}


def _txid(tx: CMutableTransaction) -> str:
    return bytes(tx.GetTxid())[::-1].hex()


def _witness(rpc: RPC, txid: str) -> list[bytes]:
    return [bytes.fromhex(x) for x in rpc.getrawtransaction(txid, True)["vin"][0]["txinwitness"]]


def _coin(rpc: RPC, txid: str, vout: int = 0) -> Coin:
    o = rpc.getrawtransaction(txid, True)["vout"][vout]
    return Coin(txid, vout, round(o["value"] * 1e8), bytes.fromhex(o["scriptPubKey"]["hex"]))


@dataclass(frozen=True)
class Outcome:
    won: bool
    win_label: bytes | None
    retained_index: int | None
    per_instance: list[dict[str, Any]]


class Participant:
    def __init__(self, rpc: RPC, manifest: GameManifest, verify_setup: SetupVerifier, name: str) -> None:
        self.rpc, self.m, self.name = rpc, manifest, name
        self.setup_journal = verify_setup(manifest)  # mandatory: no proof, no entry
        self.circuit = game_circuit(bytes.fromhex(manifest.com))
        if self.circuit.fingerprint() != manifest.circuit_fingerprint:
            raise ValueError("circuit fingerprint mismatch")
        self.key = CCoinKey.from_secret_bytes(os.urandom(32))
        self.lamport = ct.Lamport.generate(X_BITS)
        self.commitments: list[bytes] = []
        self.retained: list[int] = []
        self.publics: list[GarbledPublic] = []
        self.host_labels: list[list[bytes]] = []
        self.terms_: ct.ContractTerms | None = None
        self.assert_tx: CMutableTransaction | None = None
        self.contract_coin: Coin | None = None
        self.host_presig = b""

    @property
    def pk(self) -> bytes:
        return bytes(self.key.xonly_pub)

    def stake_coin(self, amount: int) -> Coin:
        """This party's own funds for the entry (a regtest faucet stands in for its wallet)."""
        _, (coin,) = fund(self.rpc, [(amount, bytes(p2tr_key(self.key)))], confirm=False)
        return coin

    def sign_funding(self, tx: CMutableTransaction, idx: int, spent: list[Coin]) -> None:
        sign_p2tr_key(tx, idx, spent, self.key)

    def choose(self, publics: list[GarbledPublic]) -> list[int]:
        if len(publics) != self.m.n_instances:
            raise ValueError("wrong number of instances")
        self.publics = publics
        self.commitments = [p.commitment() for p in publics]
        rng = secrets.SystemRandom()
        self.retained = sorted(rng.sample(range(len(publics)), self.m.n_retained))
        return self.retained

    def verify(self, opened: dict[int, bytes], host_labels: list[list[bytes]]) -> int:
        """Cut-and-choose: every non-retained instance must re-garble to its prior commitment."""
        if sorted(opened) != [i for i in range(self.m.n_instances) if i not in self.retained]:
            raise ValueError("host did not open exactly the non-retained instances")
        for i, seed in opened.items():
            if not verify_opened(self.circuit, seed, self.commitments[i]):
                raise ValueError(f"instance {i} is not an honest garbling of the game circuit")
        for j, labels in zip(self.retained, host_labels, strict=True):
            pairs = self.publics[j].host_label_hashes
            if any(ct.sha(lab) not in pair for lab, pair in zip(labels, pairs, strict=True)):
                raise ValueError(f"host input labels of instance {j} are not committed")
        self.host_labels = host_labels
        return len(opened)

    def terms(self, host_pk: bytes) -> ct.ContractTerms:
        pubs = [self.publics[j] for j in self.retained]
        self.terms_ = ct.ContractTerms(
            host_pk=host_pk, part_pk=self.pk, lamport=self.lamport.hashes,
            label_hashes=[p.x_label_hashes for p in pubs],
            win_hashes=[p.output_label_hashes[OUT_WIN][1] for p in pubs],
            abort_csv=self.m.abort_csv, timeout_csv=self.m.timeout_csv, settle_csv=self.m.settle_csv,
        )  # fmt: skip
        return self.terms_

    def prepare(self, contract_coin: Coin) -> tuple[CMutableTransaction, CMutableTransaction, bytes]:
        """Build the assert and deliver templates (fees fixed now) and presign deliver."""
        t = self.terms_
        assert t
        self.contract_coin = contract_coin
        a_script, a_cb = ct.leaf(t.contract_tree(), "assert")
        atx = new_tx([contract_coin], [(contract_coin.value, ct.tree_spk(t.asserted_tree()))])
        set_witness(atx, 0, ct.assert_witness([bytes(32)] * X_BITS, bytes(64), bytes(64), a_script, a_cb))
        atx.vout[0].nValue = contract_coin.value - vsize(atx) * FEERATE
        asserted = Coin(_txid(atx), 0, atx.vout[0].nValue, ct.tree_spk(t.asserted_tree()))
        d_script, d_cb = ct.leaf(t.asserted_tree(), "deliver")
        dtx = new_tx([asserted], [(asserted.value, ct.tree_spk(t.delivered_tree()))])
        dummy_labels = [[bytes(16)] * X_BITS for _ in self.retained]
        dummy = ct.deliver_witness([bytes(32)] * X_BITS, dummy_labels, bytes(64), bytes(64), d_script, d_cb)
        set_witness(dtx, 0, dummy)
        dtx.vout[0].nValue = asserted.value - vsize(dtx) * FEERATE
        presig = self.key.sign_schnorr_no_tweak(d_script.sighash_schnorr(dtx, 0, [asserted.txout()]))
        self.assert_tx = atx
        return atx, dtx, presig

    def check_host_presig(self, sig: bytes) -> None:
        assert self.terms_ and self.assert_tx and self.contract_coin
        a_script, _ = ct.leaf(self.terms_.contract_tree(), "assert")
        sh = a_script.sighash_schnorr(self.assert_tx, 0, [self.contract_coin.txout()])
        if not XOnlyPubKey(self.terms_.host_pk).verify_schnorr(sh, sig):
            raise ValueError("invalid host presignature on the assert transaction")
        self.host_presig = sig

    def assert_guess(self, x: bytes) -> str:
        """Publish the guess: one Lamport preimage per bit. Binding and one-shot."""
        assert self.terms_ and self.assert_tx and self.contract_coin
        a_script, a_cb = ct.leaf(self.terms_.contract_tree(), "assert")
        sig = self.key.sign_schnorr_no_tweak(
            a_script.sighash_schnorr(self.assert_tx, 0, [self.contract_coin.txout()])
        )
        pre = self.lamport.reveal(bytes_to_bits(x))
        set_witness(self.assert_tx, 0, ct.assert_witness(pre, sig, self.host_presig, a_script, a_cb))
        return broadcast(self.rpc, self.assert_tx)

    def timeout(self, assert_txid: str) -> str:
        assert self.terms_
        coin = _coin(self.rpc, assert_txid)
        script, cb = ct.leaf(self.terms_.asserted_tree(), "timeout")
        tx = new_tx([coin], [(coin.value - 300, bytes(p2tr_key(self.key)))], sequence=self.m.timeout_csv)
        set_witness(tx, 0, [self.key.sign_schnorr_no_tweak(script.sighash_schnorr(tx, 0, [coin.txout()])),
                            bytes(script), cb])  # fmt: skip
        return broadcast(self.rpc, tx)

    def evaluate(self, deliver_txid: str) -> Outcome:
        """Evaluate every retained instance on the labels the host was forced to publish."""
        _, x_labels = ct.parse_deliver_witness(_witness(self.rpc, deliver_txid), X_BITS, len(self.retained))
        results: list[dict[str, Any]] = []
        win_label, win_idx = None, None
        for n, j in enumerate(self.retained):
            try:
                bits, labels = evaluate(self.circuit, self.publics[j], x_labels[n], self.host_labels[n])
            except EvaluationError as e:  # only possible for a cheating garbler
                results.append({"instance": j, "error": str(e)})
                continue
            results.append({"instance": j, "win": bits[OUT_WIN], "eq": bits[OUT_EQ], "o1": bits[OUT_O1]})
            if bits[OUT_WIN] and win_label is None:
                win_label, win_idx = labels[OUT_WIN], n
        return Outcome(win_label is not None, win_label, win_idx, results)

    def claim(self, deliver_txid: str, outcome: Outcome) -> str:
        assert self.terms_ and outcome.win_label is not None and outcome.retained_index is not None
        coin = _coin(self.rpc, deliver_txid)
        script, cb = ct.leaf(self.terms_.delivered_tree(), f"win{outcome.retained_index}")
        tx = new_tx([coin], [(coin.value - 300, bytes(p2tr_key(self.key)))])
        sig = self.key.sign_schnorr_no_tweak(script.sighash_schnorr(tx, 0, [coin.txout()]))
        set_witness(tx, 0, [outcome.win_label, sig, bytes(script), cb])
        return broadcast(self.rpc, tx)


FUND_FEE_SHARE = 600


def play_entry(host: Host, player: Participant, guess: list[str], emit: Emit, *, host_stalls: bool = False
               ) -> dict[str, Any]:  # fmt: skip
    """One complete entry. Each step only uses values the acting party legitimately holds."""
    rpc, m, entry = host.rpc, player.m, player.name
    x = answer_hash(guess)
    emit("guess", tips=sorted(set(guess)), x=x.hex(), setup=player.setup_journal)

    publics = host.offer(entry)
    emit("offer", n=len(publics), commitments=[p.commitment().hex()[:12] for p in publics],
         table_bytes=len(publics[0].tables), and_gates=host.circuit.and_count)  # fmt: skip
    retained = player.choose(publics)
    emit("choose", retained=retained)
    opened, host_labels = host.open(entry, retained)
    checked = player.verify(opened, host_labels)
    emit("verified", opened=sorted(opened), checked=checked, cheat_probability=m.cheat_probability)

    terms = player.terms(host.pk)
    pc = player.stake_coin(m.entry_fee + FUND_FEE_SHARE)
    hc = host.stake_coin(m.bounty + FUND_FEE_SHARE)
    mine(rpc)
    stake = m.entry_fee + m.bounty
    spk = ct.tree_spk(terms.contract_tree())
    fund_tx = new_tx([pc, hc], [(stake, spk)])
    contract_coin = Coin(_txid(fund_tx), 0, stake, spk)
    atx, dtx, presig = player.prepare(contract_coin)
    player.check_host_presig(host.accept_terms(entry, terms, atx, contract_coin, dtx, presig))
    player.sign_funding(fund_tx, 0, [pc, hc])
    host.sign_funding(fund_tx, 1, [pc, hc])
    fund_txid = broadcast(rpc, fund_tx)
    mine(rpc)
    emit("funded", txid=fund_txid, stake=stake, entry_fee=m.entry_fee, bounty=m.bounty,
         contract_address=address(CScript(spk)))  # fmt: skip

    assert_txid = player.assert_guess(x)
    mine(rpc)
    emit("asserted", txid=assert_txid, vsize=vsize(atx), bits=bytes_to_bits(x))

    if host_stalls:
        mine(rpc, m.timeout_csv)
        txid = player.timeout(assert_txid)
        mine(rpc)
        emit("timeout", txid=txid, value=_coin(rpc, txid).value)
        return {"result": "timeout", "txid": txid}

    deliver_txid, bits = host.deliver(entry, assert_txid)
    mine(rpc)
    emit("delivered", txid=deliver_txid, vsize=rpc.getrawtransaction(deliver_txid, True)["vsize"],
         labels=len(retained) * X_BITS, bits_match=bits == bytes_to_bits(x))  # fmt: skip

    outcome = player.evaluate(deliver_txid)
    emit("evaluated", won=outcome.won, instances=outcome.per_instance)
    if outcome.won:
        txid = player.claim(deliver_txid, outcome)
        mine(rpc)
        emit("claimed", txid=txid, value=_coin(rpc, txid).value)
        return {"result": "won", "txid": txid, "instances": outcome.per_instance}
    mine(rpc, m.settle_csv)
    txid = host.settle(entry, deliver_txid)
    mine(rpc)
    emit("settled", txid=txid, value=_coin(rpc, txid).value)
    return {"result": "lost", "txid": txid, "instances": outcome.per_instance}
