"""Format-only guest inputs exercise the Merkle ambiguity guard without mining or grinding.

These fixtures are not consensus-valid blocks and do not claim a valid-chain attack receipt.
The ordinary regtest ZK tests separately protect honest-history behavior and node anchoring.
"""

import hashlib
import os
import struct
import subprocess
from pathlib import Path

import pytest

from coinjoinctf import zk
from coinjoinctf.stage import owned_spks

pytestmark = pytest.mark.skipif(not zk.BINARY.exists(), reason="zk binary not built")


def sha256d(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def transaction(script: bytes, witness: bool = False) -> tuple[bytes, bytes]:
    version, locktime = struct.pack("<I", 2), bytes(4)
    body = b"\x01" + bytes(32) + bytes(4) + b"\x00" + b"\xff" * 4
    body += b"\x01" + struct.pack("<Q", 1000) + bytes([len(script)]) + script
    stripped = version + body + locktime
    raw = version + b"\x00\x01" + body + b"\x01\x01x" + locktime if witness else stripped
    return raw, stripped


def guest_input(size: int, witness: bool) -> bytes:
    seed, nonce = bytes.fromhex("11" * 32), bytes.fromhex("22" * 32)
    owned, owned_stripped = transaction(next(iter(owned_spks(seed, 1))))
    u0 = sha256d(owned_stripped)
    first_header = struct.pack("<I", 1) + bytes(32) + u0 + bytes(12)
    first_block = first_header + b"\x01" + owned
    raw, stripped = transaction(b"\x51" * (size - 60), witness)
    assert len(stripped) == size
    if size == 64:
        # The same hash is both a txid and the parent of these two 32-byte leaves.
        assert sha256d(stripped) == sha256d(stripped[:32] + stripped[32:])
    second_header = struct.pack("<I", 1) + sha256d(first_header) + sha256d(stripped) + bytes(12)
    second_block = second_header + b"\x01" + raw
    return (
        seed
        + nonce
        + struct.pack("<I", 1)
        + u0
        + struct.pack("<II", 0, 2)
        + struct.pack("<I", len(first_block))
        + first_block
        + struct.pack("<I", len(second_block))
        + second_block
    )


@pytest.mark.parametrize("witness", [False, True])
@pytest.mark.parametrize("size", [63, 64, 65])
def test_guest_rejects_only_ambiguous_stripped_length(tmp_path: Path, size: int, witness: bool) -> None:
    source, receipt = tmp_path / "input.bin", tmp_path / "receipt.bin"
    source.write_bytes(guest_input(size, witness))
    env = dict(os.environ, RISC0_DEV_MODE="1")
    result = subprocess.run(
        [str(zk.BINARY), "prove", str(source), str(receipt)],
        capture_output=True,
        text=True,
        env=env,
    )
    if size == 64:
        assert result.returncode != 0
        assert "ambiguous 64-byte stripped transaction" in result.stderr
        assert not receipt.exists()
    else:
        assert result.returncode == 0, result.stderr
        journal, _ = zk.verify_receipt(receipt, allow_fake=True)
        assert journal.n_tips == 1


def test_missing_receipt_does_not_trigger_proving(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def unexpected(*args, **kwargs):
        raise AssertionError("verification must never regenerate a receipt")

    monkeypatch.setattr(zk, "prove", unexpected)
    with pytest.raises(zk.SetupProofError, match="missing"):
        zk.verify_receipt(tmp_path / "absent.receipt")
