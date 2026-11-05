"""One game end to end (stage, setup proof, entries, audit, reveal), shared by the CLI and web UI.

The demo runs host and participant in one process, but each step only hands the participant what
the protocol gives it. State directory (default tmp/game):
  stage.json, host.json   host-private (tumbler seed, tips, commitment randomness), mode 0600
  manifest.json, setup.receipt, public.json, entries/*.json   public
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import time
from pathlib import Path
from typing import Any

from coinjoinctf import zk
from coinjoinctf.audit import Transcript, audit_entry, host_transcript
from coinjoinctf.game import Emit, GameManifest, History, Host, Participant, play_entry
from coinjoinctf.rpc import RPC
from coinjoinctf.stage import Stage, StageConfig, StageResult

DEFAULT_STATE = Path("tmp/game")
_PARAMS = ("n_instances", "n_retained", "entry_fee", "bounty", "abort_csv", "timeout_csv", "settle_csv")


def _write_private(path: Path, data: str) -> None:
    # mkstemp creates mode 0600 before the first secret byte, regardless of the process umask.
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


class Session:
    def __init__(
        self, rpc: RPC, state: Path = DEFAULT_STATE, emit: Emit | None = None, *, dev_proof: bool = False
    ):
        self.rpc, self.state, self.dev_proof = rpc, state, dev_proof
        self.emit: Emit = emit or (lambda kind, **data: None)
        self.state.mkdir(parents=True, exist_ok=True)
        self.stage: StageResult | None = None
        self.manifest: GameManifest | None = None
        self._host: Host | None = None
        self.load()

    def _p(self, name: str) -> Path:
        return self.state / name

    def load(self) -> None:
        if self._p("stage.json").exists():
            self.stage = StageResult.model_validate_json(self._p("stage.json").read_text())
        if self._p("manifest.json").exists():
            self.manifest = GameManifest.model_validate_json(self._p("manifest.json").read_text())

    @property
    def entries(self) -> list[str]:
        d = self._p("entries")
        return sorted(p.stem for p in d.glob("*.json")) if d.exists() else []

    def run_stage(self, cfg: StageConfig | None = None) -> StageResult:
        for name in ("manifest.json", "host.json", "setup.receipt"):
            self._p(name).unlink(missing_ok=True)
        shutil.rmtree(self._p("entries"), ignore_errors=True)
        self.manifest, self._host = None, None
        self.emit("stage_start")
        res = Stage(self.rpc, cfg, lambda kind, data: self.emit(kind, **data)).run()
        _write_private(self._p("stage.json"), res.model_dump_json())
        self._p("public.json").write_text(json.dumps(res.public()))
        self.stage = res
        self.emit("stage_done", u0=res.u0, start_height=res.start_height, end_height=res.end_height,
                  txs=len(res.txs), outputs=sum(len(t["outputs"]) for t in res.txs))  # fmt: skip
        return res

    def history(self) -> History:
        s = self.stage
        assert s is not None, "run the stage first"
        return History(
            u0=s.u0, start_height=s.start_height, end_height=s.end_height, start_hash=s.start_hash,
            end_hash=s.end_hash, wallet_commitment=s.wallet_commitment(), key_limit=s.key_limit,
        )  # fmt: skip

    def setup(self, **params: int) -> GameManifest:
        """Host: commit to the answer and prove the setup statement (mandatory for entrants)."""
        s = self.stage
        assert s is not None, "run the stage first"
        r = os.urandom(32)
        host = Host(self.rpc, self.history(), s.tips, r=r, **params)
        self.emit("proving", dev=self.dev_proof, blocks=s.end_height - s.start_height + 1)
        t0 = time.time()
        receipt = self._p("setup.receipt")
        out = zk.prove(
            self.rpc, bytes.fromhex(s.tumbler_seed), r, s.key_limit, s.u0, s.start_height, s.end_height,
            receipt, dev=self.dev_proof,
        )  # fmt: skip
        manifest = host.manifest(str(receipt.resolve()))
        _write_private(self._p("host.json"), json.dumps({"r": r.hex()}))
        self._p("manifest.json").write_text(manifest.model_dump_json(indent=1))
        self.manifest, self._host = manifest, host
        self.emit(
            "setup", manifest=manifest.model_dump(), journal=out["journal_fields"], cycles=out["cycles"],
            seconds=round(time.time() - t0, 1), fake=out["fake"], image_id=out["image_id"],
        )  # fmt: skip
        return manifest

    @property
    def host(self) -> Host:
        if self._host is None:
            assert self.stage and self.manifest, "run stage and setup first"
            r = bytes.fromhex(json.loads(self._p("host.json").read_text())["r"])
            params = {k: getattr(self.manifest, k) for k in _PARAMS}
            self._host = Host(self.rpc, self.manifest.history, self.stage.tips, r=r, **params)
        return self._host

    def play(self, guess: list[str], name: str | None = None, *, stall: bool = False) -> dict[str, Any]:
        """Participant entry. The setup proof is verified before anything else (no proof, no entry)."""
        assert self.manifest is not None, "run setup first"
        name = name or f"entry{len(self.entries) + 1}"
        verifier = zk.setup_verifier(self.rpc, allow_fake=self.dev_proof)
        player = Participant(self.rpc, self.manifest, verifier, name)
        self.emit("entry", name=name, setup=player.setup_journal)
        result = play_entry(self.host, player, guess, self.emit, host_stalls=stall)
        if result["result"] != "timeout":
            self._p("entries").mkdir(exist_ok=True)
            self._p(f"entries/{name}.json").write_text(host_transcript(self.host, name).model_dump_json())
        return {"name": name, **result}

    def audit(self, name: str) -> dict[str, Any]:
        """Anyone: check a finished entry from the chain, the transcript and the setup proof."""
        assert self.manifest is not None
        t = Transcript.model_validate_json(self._p(f"entries/{name}.json").read_text())
        report = audit_entry(
            self.rpc, self.manifest, t, zk.setup_verifier(self.rpc, allow_fake=self.dev_proof)
        )
        self.emit("audit", name=name, **report)
        return report

    def reveal(self) -> dict[str, Any]:
        """Optional post-game disclosure of the answer and the host's transactions."""
        s = self.stage
        assert s is not None
        data = {"tips": s.tips, "host_txids": s.host_txids, "owners": s.owners, "u0": s.u0}
        self.emit("reveal", **data)
        return data

    def demo_guesses(self) -> dict[str, list[str]]:
        """Host-side helpers for the demo: the answer, and a near miss that swaps one tip for an
        equal-valued sibling output of the same coinjoin (what a careless analyst would pick)."""
        s = self.stage
        assert s is not None
        by_tx = {t["txid"]: t for t in s.txs}
        tip = s.tips[-1]
        tx = by_tx[tip.split(":")[0]]
        value = next(o["value"] for o in tx["outputs"] if o["outpoint"] == tip)
        sibling = next(o["outpoint"] for o in tx["outputs"] if o["value"] == value and o["outpoint"] != tip)
        return {"correct": list(s.tips), "near_miss": [*s.tips[:-1], sibling]}
