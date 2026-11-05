"""Setup proof (RISC Zero): build the guest input from the node, prove, and verify the journal.

The guest (zk/methods/guest) proves, without revealing the wallet seed or the tips, that the
committed answer ``com`` encodes the complete set of tips of U0's lineage over a block range the
verifier anchors to its own node. ``stage.owned_tips`` is the Python reference of that statement.
"""

from __future__ import annotations

import json
import os
import struct
import subprocess
import tempfile
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from coinjoinctf.game import GameManifest
from coinjoinctf.rpc import RPC

ZK_DIR = Path(__file__).resolve().parents[2] / "zk"
BINARY = Path(os.environ.get("CTF_ZK_BIN", ZK_DIR / "target" / "release" / "ctf-zk"))
_JOURNAL = struct.Struct("<32sI32sI32s32sII32s")


class SetupProofError(Exception):
    pass


@dataclass(frozen=True)
class Journal:
    wallet_commitment: str
    key_limit: int
    u0: str
    start_hash: str  # RPC display order
    end_hash: str
    n_blocks: int
    n_tips: int
    com: str

    @classmethod
    def parse(cls, data: bytes) -> Journal:
        if len(data) != _JOURNAL.size:
            raise SetupProofError(f"journal must be {_JOURNAL.size} bytes, got {len(data)}")
        wc, limit, u0_txid, u0_vout, start, end, n_blocks, n_tips, com = _JOURNAL.unpack(data)
        return cls(
            wc.hex(), limit, f"{u0_txid[::-1].hex()}:{u0_vout}", start[::-1].hex(), end[::-1].hex(),
            n_blocks, n_tips, com.hex(),
        )  # fmt: skip


def guest_input(rpc: RPC, seed: bytes, r: bytes, key_limit: int, u0: str, start: int, end: int) -> bytes:
    txid, vout = u0.split(":")
    parts = [
        seed,
        r,
        struct.pack("<I", key_limit),
        bytes.fromhex(txid)[::-1],
        struct.pack("<II", int(vout), end - start + 1),
    ]
    for h in range(start, end + 1):
        raw = bytes.fromhex(rpc.getblock(rpc.getblockhash(h), 0))
        parts += [struct.pack("<I", len(raw)), raw]
    return b"".join(parts)


def _run(*args: str, dev: bool) -> dict[str, Any]:
    if not BINARY.exists():
        raise SetupProofError(f"{BINARY} not found; run `cargo build --release` in {ZK_DIR}")
    env = {k: v for k, v in os.environ.items() if k != "RISC0_DEV_MODE"}
    if dev:
        env["RISC0_DEV_MODE"] = "1"
    res = subprocess.run([str(BINARY), *args], capture_output=True, text=True, env=env, check=False)
    if res.returncode:
        lines = res.stderr.strip().splitlines()
        raise SetupProofError(lines[-1] if lines else f"ctf-zk exited with {res.returncode}")
    return dict(json.loads(res.stdout.strip().splitlines()[-1]))


def prove(
    rpc: RPC, seed: bytes, r: bytes, key_limit: int, u0: str, start: int, end: int, receipt: Path,
    *, dev: bool = False,
) -> dict[str, Any]:  # fmt: skip
    """Prove the setup statement. dev=True makes a fake receipt (fast; only for iteration)."""
    receipt.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as d:  # the input contains the seed: keep it private
        inp = Path(d) / "input.bin"
        inp.write_bytes(guest_input(rpc, seed, r, key_limit, u0, start, end))
        out = _run("prove", str(inp), str(receipt), dev=dev)
    out["journal_fields"] = asdict(Journal.parse(bytes.fromhex(out["journal"])))
    return out


def verify_receipt(receipt: Path, *, allow_fake: bool = False) -> tuple[Journal, dict[str, Any]]:
    out = _run("verify", str(receipt), dev=allow_fake)
    if out["fake"] and not allow_fake:
        raise SetupProofError("dev-mode (fake) receipt")
    return Journal.parse(bytes.fromhex(out["journal"])), out


def setup_verifier(rpc: RPC, *, allow_fake: bool = False) -> Callable[[GameManifest], dict[str, Any]]:
    """The participant's mandatory pre-entry check: a valid receipt whose journal matches the
    manifest, over the blocks the participant's own node has at the stated heights."""

    def verify(m: GameManifest) -> dict[str, Any]:
        if not m.proof:
            raise SetupProofError("manifest carries no setup proof")
        j, out = verify_receipt(Path(m.proof), allow_fake=allow_fake)
        h = m.history
        checks = {
            "wallet_commitment": j.wallet_commitment == h.wallet_commitment,
            "key_limit": j.key_limit == h.key_limit,
            "u0": j.u0 == h.u0,
            "start_block": j.start_hash == h.start_hash == rpc.getblockhash(h.start_height),
            "end_block": j.end_hash == h.end_hash == rpc.getblockhash(h.end_height),
            "n_blocks": j.n_blocks == h.end_height - h.start_height + 1,
            "n_tips": j.n_tips == m.n_tips,
            "com": j.com == m.com,
        }
        bad = [k for k, ok in checks.items() if not ok]
        if bad:
            raise SetupProofError(f"setup proof does not match the manifest: {', '.join(bad)}")
        return {"image_id": out["image_id"], "fake": out["fake"], **asdict(j)}

    return verify
