"""Transaction plumbing over python-bitcointx: keys, P2WPKH / P2TR spends, funding, fees."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

import bitcointx
from bitcointx.core import (
    CMutableTransaction,
    CMutableTxIn,
    CMutableTxInWitness,
    CMutableTxOut,
    COutPoint,
    CTransaction,
    CTxOut,
    lx,
)
from bitcointx.core.key import XOnlyPubKey
from bitcointx.core.script import (
    SIGHASH_ALL,
    SIGVERSION_WITNESS_V0,
    CScript,
    CScriptWitness,
    SignatureHash,
    SignatureHashSchnorr,
)
from bitcointx.wallet import (
    CCoinAddress,
    CCoinKey,
    P2PKHCoinAddress,
    P2TRCoinAddress,
    P2WPKHCoinAddress,
)

from coinjoinctf.rpc import RPC, mine

bitcointx.select_chain_params("bitcoin/regtest")

FEERATE = 2  # sat/vB, regtest


def derive_key(*parts: str | bytes) -> CCoinKey:
    h = hashlib.sha256(b"coinjoinctf/key")
    for p in parts:
        h.update(p.encode() if isinstance(p, str) else p)
        h.update(b"/")
    return CCoinKey.from_secret_bytes(h.digest())


def p2wpkh(key: CCoinKey) -> CScript:
    return P2WPKHCoinAddress.from_pubkey(key.pub).to_scriptPubKey()


def p2tr_key(key: CCoinKey) -> CScript:
    return P2TRCoinAddress.from_xonly_pubkey(key.xonly_pub).to_scriptPubKey()


def address(spk: CScript) -> str:
    return str(CCoinAddress.from_scriptPubKey(spk))


@dataclass(frozen=True)
class Coin:
    txid: str
    vout: int
    value: int
    spk: bytes

    @property
    def outpoint(self) -> str:
        return f"{self.txid}:{self.vout}"

    def txout(self) -> CTxOut:
        return CTxOut(self.value, CScript(self.spk))


def new_tx(
    inputs: list[Coin], outputs: list[tuple[int, bytes]], sequence: int = 0xFFFFFFFD
) -> CMutableTransaction:
    return CMutableTransaction(
        vin=[CMutableTxIn(COutPoint(lx(c.txid), c.vout), nSequence=sequence) for c in inputs],
        vout=[CMutableTxOut(v, CScript(s)) for v, s in outputs],
        nVersion=2,
    )


def sign_p2wpkh(tx: CMutableTransaction, idx: int, coin: Coin, key: CCoinKey) -> None:
    code = P2PKHCoinAddress.from_pubkey(key.pub).to_scriptPubKey()
    sh = SignatureHash(code, tx, idx, SIGHASH_ALL, amount=coin.value, sigversion=SIGVERSION_WITNESS_V0)
    tx.wit.vtxinwit[idx] = CMutableTxInWitness(CScriptWitness([key.sign(sh) + bytes([SIGHASH_ALL]), key.pub]))


def sign_p2tr_key(tx: CMutableTransaction, idx: int, spent: list[Coin], key: CCoinKey) -> None:
    sh = SignatureHashSchnorr(tx, idx, [c.txout() for c in spent])
    tx.wit.vtxinwit[idx] = CMutableTxInWitness(CScriptWitness([key.sign_schnorr_tweaked(sh)]))


def set_witness(tx: CMutableTransaction, idx: int, items: list[bytes]) -> None:
    tx.wit.vtxinwit[idx] = CMutableTxInWitness(CScriptWitness(items))


def vsize(tx: CMutableTransaction | CTransaction) -> int:
    return int(tx.get_virtual_size())


def broadcast(rpc: RPC, tx: CMutableTransaction | CTransaction) -> str:
    return str(rpc.sendrawtransaction(tx.serialize().hex()))


def fund(rpc: RPC, outputs: list[tuple[int, bytes]], confirm: bool = True) -> tuple[str, list[Coin]]:
    """Pay ``outputs`` from the miner wallet in one transaction; return created coins in order."""
    amounts = [{address(CScript(spk)): v / 1e8} for v, spk in outputs]
    res = rpc.send(amounts, None, "unset", 2)
    txid = res["txid"]
    raw = rpc.getrawtransaction(txid, True)
    coins: list[Coin] = []
    used: set[int] = set()
    for v, spk in outputs:
        for o in raw["vout"]:
            n = o["n"]
            if n in used:
                continue
            if bytes.fromhex(o["scriptPubKey"]["hex"]) == bytes(spk) and round(o["value"] * 1e8) == v:
                coins.append(Coin(txid, n, v, bytes(spk)))
                used.add(n)
                break
    if confirm:
        mine(rpc)
    return txid, coins


__all__ = [
    "CCoinKey",
    "Coin",
    "XOnlyPubKey",
    "address",
    "broadcast",
    "derive_key",
    "fund",
    "new_tx",
    "p2tr_key",
    "p2wpkh",
    "set_witness",
    "sign_p2tr_key",
    "sign_p2wpkh",
    "vsize",
]
