"""JoinMarket stage: unit checks for bond weighting and a full regtest run against the oracle."""

import collections
import os
import random

import pytest

from coinjoinctf.chain import Coin
from coinjoinctf.rpc import RPC, RPCError, node
from coinjoinctf.stage import (
    YEAR,
    Bond,
    Maker,
    Stage,
    StageConfig,
    Utxo,
    Wallet,
    choose_makers,
    owned_tips,
    tumbler_schedule,
    wallet_key,
)


def _maker(name: str, bond_btc: float, years: float) -> Maker:
    w = Wallet(name, os.urandom(32))
    key, spk = w.new_output()
    w.utxos.append(Utxo(Coin("00" * 32, len(name), 500_000_000, spk), 0, key))
    bond = Bond(Coin("11" * 32, 0, int(bond_btc * 1e8), b""), int(years * YEAR), 0) if bond_btc else None
    return Maker(w, bond, True, 0.0001, 100_000)


def test_bond_value_grows_with_lock_and_amount() -> None:
    assert Bond(Coin("", 0, 10**8, b""), int(2 * YEAR), 0).value(0) > Bond(
        Coin("", 0, 10**8, b""), int(YEAR), 0
    ).value(0)
    assert Bond(Coin("", 0, 2 * 10**8, b""), int(YEAR), 0).value(0) > Bond(
        Coin("", 0, 10**8, b""), int(YEAR), 0
    ).value(0)


def test_choice_is_bond_weighted_with_bondless_allowance() -> None:
    makers = [_maker("big", 5, 4), _maker("small", 0.5, 1), _maker("none", 0, 0)]
    rng = random.Random(1)
    first = collections.Counter(
        choose_makers(rng, makers, 10**7, 1, 0, set())[0].wallet.name for _ in range(4000)
    )
    assert first["big"] > first["small"] > 0 and first["none"] > 0
    assert first["none"] < 0.125 * 4000  # only through the bondless allowance (1/3 of 12.5%)


def test_schedule_ends_in_destinations() -> None:
    steps = tumbler_schedule(random.Random(3))
    assert [s.final for s in steps][-3:] == [True] * 3 and not any(s.final for s in steps[:-3])
    assert steps[-1].fraction is None  # last destination sweeps the final mixdepth
    for md in range(3):  # each intermediate mixdepth ends with a sweep
        assert [s for s in steps if s.mixdepth == md][-1].fraction is None


def test_wallet_key_is_deterministic() -> None:
    seed = os.urandom(32)
    k1, k2 = wallet_key(seed, 5), wallet_key(seed, 5)
    assert k1 is not None and k2 is not None and k1.pub == k2.pub
    k3 = wallet_key(seed, 6)
    assert k3 is not None and k3.pub != k1.pub


@pytest.fixture(scope="module")
def rpc() -> RPC:
    try:
        return node()
    except (RPCError, OSError):
        pytest.skip("regtest node not running")


@pytest.mark.regtest
def test_stage_run_matches_oracle(rpc: RPC) -> None:
    res = Stage(rpc, StageConfig(seed=11)).run()
    seed = bytes.fromhex(res.tumbler_seed)
    assert owned_tips(rpc, seed, res.key_limit, res.u0, res.start_height, res.end_height) == res.tips
    assert len(res.tips) == 3
    by_id = {t["txid"]: t for t in res.txs}
    for txid in res.host_txids[1:]:  # every tumbler step is a coinjoin with >= 3 makers
        tx = by_id[txid]
        values = collections.Counter(o["value"] for o in tx["outputs"])
        assert tx["kind"] == "coinjoin" and values[tx["meta"]["amount"]] >= 4
    assert sum(1 for t in res.txs if t["txid"] not in res.host_txids) > len(res.host_txids)
    public = res.public()
    assert not {"tips", "tumbler_seed", "owners", "host_txids"} & public.keys()
    for m in res.makers:  # fidelity bonds are real, unspent P2WSH outputs
        if m["bond"]:
            txid, n = m["bond"]["outpoint"].split(":")
            out = rpc.gettxout(txid, int(n))
            assert out and out["scriptPubKey"]["type"] == "witness_v0_scripthash"
    other = os.urandom(32)
    with pytest.raises(ValueError, match="not owned"):
        owned_tips(rpc, other, res.key_limit, res.u0, res.start_height, res.end_height)
    with pytest.raises(ValueError, match="not created"):
        owned_tips(rpc, seed, res.key_limit, res.u0, res.start_height + 1, res.end_height)
