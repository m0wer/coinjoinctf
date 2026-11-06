"""Format-only guest inputs exercise the guest's rules without mining or grinding.

These fixtures are not consensus-valid blocks (inputs are not signed and amounts do not balance)
and do not claim a valid-chain attack receipt. The ordinary regtest ZK tests separately protect
honest-history behavior and node anchoring.
"""

import hashlib
import os
import struct
import subprocess
from pathlib import Path

import pytest

from coinjoinctf import zk
from coinjoinctf.chain import p2wpkh
from coinjoinctf.stage import owned_spks, wallet_key

pytestmark = pytest.mark.skipif(not zk.BINARY.exists(), reason="zk binary not built")

SEED, NONCE = bytes.fromhex("11" * 32), bytes.fromhex("22" * 32)


def sha256d(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def transaction(script: bytes, witness: bool = False) -> tuple[bytes, bytes]:
    version, locktime = struct.pack("<I", 2), bytes(4)
    body = b"\x01" + bytes(32) + bytes(4) + b"\x00" + b"\xff" * 4
    body += b"\x01" + struct.pack("<Q", 1000) + bytes([len(script)]) + script
    stripped = version + body + locktime
    raw = version + b"\x00\x01" + body + b"\x01\x01x" + locktime if witness else stripped
    return raw, stripped


def legacy_tx(inputs: list[tuple[bytes, int]], outputs: list[tuple[int, bytes]]) -> bytes:
    """A legacy transaction (txid = sha256d of these bytes) with up to 252 inputs and outputs."""
    body = bytes([len(inputs)]) + b"".join(
        t + struct.pack("<I", n) + b"\x00" + b"\xff" * 4 for t, n in inputs
    )
    body += bytes([len(outputs)]) + b"".join(struct.pack("<Q", v) + bytes([len(s)]) + s for v, s in outputs)
    return struct.pack("<I", 2) + body + bytes(4)


def merkle_root(txids: list[bytes]) -> bytes:
    level = list(txids)
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [sha256d(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


def guest_input(u0: tuple[bytes, int], blocks: list[list[tuple[bytes, bytes]]], key_limit: int = 1) -> bytes:
    """Chain blocks of (raw, stripped) transactions and frame them as the guest's private input."""
    parts = [SEED, NONCE, struct.pack("<I", key_limit), u0[0], struct.pack("<II", u0[1], len(blocks))]
    prev = bytes(32)
    for txs in blocks:
        header = struct.pack("<I", 1) + prev + merkle_root([sha256d(s) for _, s in txs]) + bytes(12)
        block = header + bytes([len(txs)]) + b"".join(raw for raw, _ in txs)
        parts += [struct.pack("<I", len(block)), block]
        prev = sha256d(header)
    return b"".join(parts)


def prove(tmp_path: Path, data: bytes) -> tuple[subprocess.CompletedProcess[str], Path]:
    source, receipt = tmp_path / "input.bin", tmp_path / "receipt.bin"
    source.write_bytes(data)
    env = dict(os.environ, RISC0_DEV_MODE="1")
    result = subprocess.run(
        [str(zk.BINARY), "prove", str(source), str(receipt)], capture_output=True, text=True, env=env
    )
    return result, receipt


def ambiguity_input(size: int, witness: bool) -> bytes:
    owned_spk = next(iter(owned_spks(SEED, 1)))
    owned, owned_stripped = transaction(owned_spk)
    u0 = sha256d(owned_stripped)
    raw, stripped = transaction(b"\x51" * (size - 60), witness)
    assert len(stripped) == size
    if size == 64:
        # The same hash is both a txid and the parent of these two 32-byte leaves.
        assert sha256d(stripped) == sha256d(stripped[:32] + stripped[32:])
    # A third block spends U0 into the wallet, so honest sizes yield a valid statement (one tip).
    spend = legacy_tx([(u0, 0)], [(900, owned_spk)])
    return guest_input((u0, 0), [[(owned, owned_stripped)], [(raw, stripped)], [(spend, spend)]])


@pytest.mark.parametrize("witness", [False, True])
@pytest.mark.parametrize("size", [63, 64, 65])
def test_guest_rejects_only_ambiguous_stripped_length(tmp_path: Path, size: int, witness: bool) -> None:
    result, receipt = prove(tmp_path, ambiguity_input(size, witness))
    if size == 64:
        assert result.returncode != 0
        assert "ambiguous 64-byte stripped transaction" in result.stderr
        assert not receipt.exists()
    else:
        assert result.returncode == 0, result.stderr
        journal, _ = zk.verify_receipt(receipt, allow_fake=True)
        assert journal.n_tips == 1


def keys(n: int) -> list[bytes]:
    return [bytes(p2wpkh(k)) for i in range(n) if (k := wallet_key(SEED, i)) is not None]


def foreign(i: int) -> bytes:
    return b"\x00\x14" + bytes([0xA0 + i]) * 20


def outside(n: int, tag: int) -> list[tuple[bytes, int]]:
    """n inputs spending coins created before the range (not lineage)."""
    return [(bytes([tag]) * 32, i) for i in range(n)]


def deposit(spk: bytes) -> tuple[bytes, tuple[bytes, int]]:
    tx = legacy_tx(outside(1, 0xEE), [(100, spk)])
    return tx, (sha256d(tx), 0)


def test_guest_rejects_unspent_u0(tmp_path: Path) -> None:
    tx, u0 = deposit(keys(1)[0])
    result, receipt = prove(tmp_path, guest_input(u0, [[(tx, tx)]]))
    assert result.returncode != 0
    assert "U0 is never spent" in result.stderr
    assert not receipt.exists()


def test_guest_rejects_lineage_without_tips(tmp_path: Path) -> None:
    tx, u0 = deposit(keys(1)[0])
    payment = legacy_tx([u0], [(90, foreign(0))])
    result, receipt = prove(tmp_path, guest_input(u0, [[(tx, tx)], [(payment, payment)]]))
    assert result.returncode != 0
    assert "no unspent tips" in result.stderr
    assert not receipt.exists()


def test_guest_reports_lineage_shape(tmp_path: Path) -> None:
    """Each minimum is witnessed by a case that a naive rule would get wrong:
    depth takes the shortest path (C joins depth 1 and 2), anonymity counts distinct scripts (C pays
    f6 twice), and foreign inputs propagate from ancestors (only A has a single outside input)."""
    k = keys(6)
    dep, u0 = deposit(k[0])
    a = legacy_tx([u0, *outside(1, 1)], [(40, k[1]), (40, foreign(1)), (15, k[2])])
    a_id = sha256d(a)  # A:0 (depth 1), A:2 (depth 1); one foreign input
    b = legacy_tx(
        [(a_id, 2), *outside(3, 2)], [(5, k[3]), (5, foreign(2)), (5, foreign(3)), (5, foreign(4)), (3, k[4])]
    )
    b_id = sha256d(b)  # B:0 and B:4 at depth 2
    c = legacy_tx(
        [(a_id, 0), (b_id, 0), *outside(2, 3)],
        [(20, k[5]), (20, foreign(5)), (20, foreign(6)), (20, foreign(6))],
    )
    e = legacy_tx(
        [(b_id, 4), *outside(4, 4)],
        [(1, k[1]), (1, foreign(7)), (1, foreign(8)), (1, foreign(9)), (1, foreign(10))],
    )
    data = guest_input(u0, [[(dep, dep)], [(a, a)], [(b, b)], [(c, c), (e, e)]], key_limit=len(k))
    result, receipt = prove(tmp_path, data)
    assert result.returncode == 0, result.stderr
    j, _ = zk.verify_receipt(receipt, allow_fake=True)
    # tips: C:0 (depth 2, anonymity 3) and E:0 (depth 3, anonymity 5); both descend from A
    assert (j.n_tips, j.tip_txs, j.min_depth, j.min_anonymity, j.min_foreign_inputs) == (2, 2, 2, 3, 1)


def test_missing_receipt_does_not_trigger_proving(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def unexpected(*args, **kwargs):
        raise AssertionError("verification must never regenerate a receipt")

    monkeypatch.setattr(zk, "prove", unexpected)
    with pytest.raises(zk.SetupProofError, match="missing"):
        zk.verify_receipt(tmp_path / "absent.receipt")
