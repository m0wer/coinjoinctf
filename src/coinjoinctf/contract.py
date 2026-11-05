"""The per-entry Taproot contract: fund -> assert (Lamport-committed guess) -> deliver | timeout.

O_contract leaves:
  assert : host sig + participant sig + one Lamport preimage per guess bit (presigned by host)
  abort  : host sig after CSV(abort_csv)        (participant never committed a guess)
O_asserted leaves:
  deliver: participant presig + host sig + for every bit i the participant's revealed preimage
           s_i AND the matching x-labels of every retained instance (hash-checked); the branch is
           chosen by s_i, so the host can only deliver labels for the bits committed on-chain
  timeout: participant sig after CSV(timeout_csv) (host withheld labels)
O_delivered leaves:
  win_m  : participant sig + preimage of H(label of output win=1) of retained instance m
  settle : host sig after CSV(settle_csv) (participant could not produce a winning label)
Internal key is the BIP341 NUMS point: no keypath spend exists. Every transition between the
three outputs is presigned by the party that would lose from a redirect.
Initial stack of deliver = n_bits * (1 + M) + 2 signatures; BIP342 caps it at 1000.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from typing import Any

from bitcointx.core.key import XOnlyPubKey
from bitcointx.core.script import (
    OP_1,
    OP_BOOLOR,
    OP_CHECKSEQUENCEVERIFY,
    OP_CHECKSIG,
    OP_CHECKSIGVERIFY,
    OP_DROP,
    OP_DUP,
    OP_ELSE,
    OP_ENDIF,
    OP_EQUAL,
    OP_EQUALVERIFY,
    OP_IF,
    OP_SHA256,
    OP_SWAP,
    OP_VERIFY,
    CScript,
    TaprootScriptTree,
)
from bitcointx.wallet import P2TRCoinAddress

NUMS = XOnlyPubKey(bytes.fromhex("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"))

HashPair = tuple[bytes, bytes]


@dataclass(frozen=True)
class Lamport:
    """One-time bit commitment: revealing secrets[i][b] commits bit i to b."""

    secrets: tuple[HashPair, ...]

    @classmethod
    def generate(cls, n_bits: int) -> Lamport:
        return cls(tuple((os.urandom(32), os.urandom(32)) for _ in range(n_bits)))

    @property
    def hashes(self) -> tuple[HashPair, ...]:
        return tuple((sha(a), sha(b)) for a, b in self.secrets)

    def reveal(self, bits: list[int]) -> list[bytes]:
        return [pair[b] for pair, b in zip(self.secrets, bits, strict=True)]


def sha(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def decode_bits(hashes: tuple[HashPair, ...], preimages: list[bytes]) -> list[int]:
    """Recover committed bits from revealed preimages (anyone can do this)."""
    return [pair.index(sha(s)) for pair, s in zip(hashes, preimages, strict=True)]


def assert_leaf(host_pk: bytes, part_pk: bytes, lamport: tuple[HashPair, ...]) -> CScript:
    ops: list[Any] = [host_pk, OP_CHECKSIGVERIFY, part_pk, OP_CHECKSIGVERIFY]
    for h0, h1 in lamport:
        ops += [OP_SHA256, OP_DUP, h0, OP_EQUAL, OP_SWAP, h1, OP_EQUAL, OP_BOOLOR, OP_VERIFY]
    return CScript(ops + [OP_1], name="assert")


def csv_leaf(pk: bytes, blocks: int, name: str) -> CScript:
    return CScript([blocks, OP_CHECKSEQUENCEVERIFY, OP_DROP, pk, OP_CHECKSIG], name=name)


MAX_STACK = 1000


def deliver_leaf(
    host_pk: bytes,
    part_pk: bytes,
    lamport: tuple[HashPair, ...],
    label_hashes: list[tuple[HashPair, ...]],
) -> CScript:
    """label_hashes[m][i][b] = SHA256(x-label of retained instance m, bit i, value b)."""
    if len(lamport) * (1 + len(label_hashes)) + 2 > MAX_STACK:
        raise ValueError("delivery witness would exceed the BIP342 initial stack limit")
    ops: list[Any] = [host_pk, OP_CHECKSIGVERIFY, part_pk, OP_CHECKSIGVERIFY]
    for i, (h0, h1) in enumerate(lamport):
        ops += [OP_SHA256, OP_DUP, h1, OP_EQUAL, OP_IF, OP_DROP]
        for inst in label_hashes:
            ops += [OP_SHA256, inst[i][1], OP_EQUALVERIFY]
        ops += [OP_ELSE, h0, OP_EQUALVERIFY]
        for inst in label_hashes:
            ops += [OP_SHA256, inst[i][0], OP_EQUALVERIFY]
        ops += [OP_ENDIF]
    return CScript(ops + [OP_1], name="deliver")


@dataclass(frozen=True)
class ContractTerms:
    """Everything both parties agree on before funding. All fields are public."""

    host_pk: bytes
    part_pk: bytes
    lamport: tuple[HashPair, ...]
    label_hashes: list[tuple[HashPair, ...]]  # retained instances only
    win_hashes: list[bytes]  # SHA256(label of win = 1), retained instances only
    abort_csv: int
    timeout_csv: int
    settle_csv: int

    def validate(self, n_bits: int, n_instances: int) -> None:
        """Validate peer-supplied dimensions and unambiguous bit commitments before signing."""
        if len(self.lamport) != n_bits:
            raise ValueError(f"expected {n_bits} Lamport pairs")
        if len(self.label_hashes) != n_instances or len(self.win_hashes) != n_instances:
            raise ValueError("wrong number of retained label vectors")
        for group in (self.lamport, *self.label_hashes):
            if len(group) != n_bits:
                raise ValueError("wrong label vector width")
            for pair in group:
                if len(pair) != 2 or any(not isinstance(h, bytes) or len(h) != 32 for h in pair):
                    raise ValueError("expected pairs of 32-byte hashes")
                if pair[0] == pair[1]:
                    raise ValueError("zero and one hashes must be distinct")
        if any(not isinstance(h, bytes) or len(h) != 32 for h in self.win_hashes):
            raise ValueError("expected 32-byte win hashes")

    def contract_tree(self) -> TaprootScriptTree:
        leaves = [
            assert_leaf(self.host_pk, self.part_pk, self.lamport),
            csv_leaf(self.host_pk, self.abort_csv, "abort"),
        ]
        return TaprootScriptTree(leaves, internal_pubkey=NUMS)

    def asserted_tree(self) -> TaprootScriptTree:
        leaves = [
            deliver_leaf(self.host_pk, self.part_pk, self.lamport, self.label_hashes),
            csv_leaf(self.part_pk, self.timeout_csv, "timeout"),
        ]
        return TaprootScriptTree(leaves, internal_pubkey=NUMS)

    def delivered_tree(self) -> TaprootScriptTree:
        leaves = [
            CScript([self.part_pk, OP_CHECKSIGVERIFY, OP_SHA256, h, OP_EQUAL], name=f"win{m}")
            for m, h in enumerate(self.win_hashes)
        ]
        leaves.append(csv_leaf(self.host_pk, self.settle_csv, "settle"))
        return TaprootScriptTree(leaves, internal_pubkey=NUMS)


def tree_spk(tree: TaprootScriptTree) -> bytes:
    return bytes(P2TRCoinAddress.from_script_tree(tree).to_scriptPubKey())


def leaf(tree: TaprootScriptTree, name: str) -> tuple[CScript, bytes]:
    res = tree.get_script_with_control_block(name)
    assert res is not None
    script, cb = res
    return script, bytes(cb)


def assert_witness(
    preimages: list[bytes], part_sig: bytes, host_sig: bytes, script: CScript, cb: bytes
) -> list[bytes]:
    """Stack top must be host sig, then participant sig, then s_0..s_127."""
    return list(reversed(preimages)) + [part_sig, host_sig, bytes(script), cb]


def deliver_witness(
    preimages: list[bytes],
    labels: list[list[bytes]],
    part_sig: bytes,
    host_sig: bytes,
    script: CScript,
    cb: bytes,
) -> list[bytes]:
    """labels[m][i]: delivered x-label of retained instance m for bit i."""
    items: list[bytes] = []
    for i in reversed(range(len(preimages))):
        items += [labels[m][i] for m in reversed(range(len(labels)))]
        items.append(preimages[i])
    return items + [part_sig, host_sig, bytes(script), cb]


def parse_deliver_witness(items: list[bytes], n_bits: int, m: int) -> tuple[list[bytes], list[list[bytes]]]:
    """Inverse of deliver_witness: returns (preimages, labels[m][i])."""
    body = items[: n_bits * (m + 1)]
    preimages: list[bytes] = [b""] * n_bits
    labels = [[b""] * n_bits for _ in range(m)]
    pos = 0
    for i in reversed(range(n_bits)):
        for j in reversed(range(m)):
            labels[j][i] = body[pos]
            pos += 1
        preimages[i] = body[pos]
        pos += 1
    return preimages, labels


def parse_assert_witness(items: list[bytes], n_bits: int) -> list[bytes]:
    return list(reversed(items[:n_bits]))
