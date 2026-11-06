"""Setup proof against the reference oracle (needs regtest and a built zk/ binary; dev mode).

Dev mode still executes the guest for real (the journal is computed by the guest); only the seal
is fake. A real proof is exercised by the CLI, not by the test suite, because it takes minutes.
"""

import hashlib
import os
from pathlib import Path

import pytest

from coinjoinctf import zk
from coinjoinctf.circuit import answer_commitment
from coinjoinctf.game import GameManifest, History, Host, answer_hash
from coinjoinctf.rpc import RPC, RPCError, node
from coinjoinctf.stage import Stage, StageConfig, StageResult, trace_lineage

pytestmark = [
    pytest.mark.regtest,
    pytest.mark.skipif(not zk.BINARY.exists(), reason="zk binary not built"),
]


@pytest.fixture(scope="module")
def rpc() -> RPC:
    try:
        return node()
    except (RPCError, OSError):
        pytest.skip("regtest node not running")


@pytest.fixture(scope="module")
def stage(rpc: RPC) -> StageResult:
    return Stage(rpc, StageConfig(seed=5, n_makers=8, n_takers=2)).run()


def _history(res: StageResult) -> History:
    return History(
        u0=res.u0, start_height=res.start_height, end_height=res.end_height, start_hash=res.start_hash,
        end_hash=res.end_hash, wallet_commitment=res.wallet_commitment(), key_limit=res.key_limit,
    )  # fmt: skip


@pytest.fixture(scope="module")
def proven(
    rpc: RPC, stage: StageResult, tmp_path_factory: pytest.TempPathFactory
) -> tuple[GameManifest, Host, dict]:
    host = Host(rpc, _history(stage), stage.tips)
    receipt = tmp_path_factory.mktemp("zk") / "setup.receipt"
    seed = bytes.fromhex(stage.tumbler_seed)
    out = zk.prove(
        rpc, seed, host.r, stage.key_limit, stage.u0, stage.start_height, stage.end_height, receipt, dev=True
    )
    return host.manifest(str(receipt)), host, out


def test_journal_matches_oracle(stage: StageResult, proven: tuple) -> None:
    m, host, out = proven
    j = out["journal_fields"]
    assert out["fake"] is True
    assert j["n_tips"] == len(stage.tips) == m.n_tips
    assert j["com"] == answer_commitment(answer_hash(stage.tips), host.r).hex() == m.com
    assert j["wallet_commitment"] == hashlib.sha256(bytes.fromhex(stage.tumbler_seed)).hexdigest()
    assert (j["u0"], j["start_hash"], j["end_hash"]) == (stage.u0, stage.start_hash, stage.end_hash)


def test_journal_shape_matches_oracle(rpc: RPC, stage: StageResult, proven: tuple) -> None:
    j = proven[2]["journal_fields"]
    seed = bytes.fromhex(stage.tumbler_seed)
    ref = trace_lineage(rpc, seed, stage.key_limit, stage.u0, stage.start_height, stage.end_height)
    assert ref.tips == stage.tips
    shape = ("tip_txs", "min_depth", "min_anonymity", "min_foreign_inputs")
    assert {k: j[k] for k in shape} == {k: getattr(ref, k) for k in shape}
    # The tumbler: three destination coinjoins after four mixdepth hops, >= 3 makers per coinjoin.
    assert ref.tip_txs == 3 and ref.min_depth >= 4
    assert ref.min_anonymity >= 4 and ref.min_foreign_inputs >= 3


def test_verifier_accepts_matching_manifest(rpc: RPC, proven: tuple) -> None:
    m, _, _ = proven
    assert zk.setup_verifier(rpc, allow_fake=True)(m)["n_tips"] == m.n_tips


def test_verifier_rejects_fake_receipt_in_production_mode(rpc: RPC, proven: tuple) -> None:
    with pytest.raises(zk.SetupProofError):
        zk.setup_verifier(rpc)(proven[0])


@pytest.mark.parametrize(
    "change",
    [
        {"n_tips": 99},
        {"com": "00" * 32},
        {"history": {"key_limit": 1}},
        {"history": {"end_height": -1}},
    ],
)
def test_verifier_rejects_mismatched_manifest(rpc: RPC, proven: tuple, change: dict) -> None:
    m: GameManifest = proven[0]
    if "history" in change:
        h = change["history"]
        if h.get("end_height") == -1:  # claim a shorter range than the proof covers
            h = {
                "end_height": m.history.end_height - 1,
                "end_hash": rpc.getblockhash(m.history.end_height - 1),
            }
        m = m.model_copy(update={"history": m.history.model_copy(update=h)})
    else:
        m = m.model_copy(update=change)
    with pytest.raises(zk.SetupProofError, match="does not match"):
        zk.setup_verifier(rpc, allow_fake=True)(m)


def test_guest_rejects_foreign_wallet(rpc: RPC, stage: StageResult, tmp_path: Path) -> None:
    with pytest.raises(zk.SetupProofError):
        zk.prove(
            rpc, os.urandom(32), os.urandom(32), stage.key_limit, stage.u0, stage.start_height,
            stage.end_height, tmp_path / "r", dev=True,
        )  # fmt: skip


def test_guest_rejects_range_without_u0(rpc: RPC, stage: StageResult, tmp_path: Path) -> None:
    seed = bytes.fromhex(stage.tumbler_seed)
    with pytest.raises(zk.SetupProofError):
        zk.prove(
            rpc, seed, os.urandom(32), stage.key_limit, stage.u0, stage.start_height + 1, stage.end_height,
            tmp_path / "r", dev=True,
        )  # fmt: skip
