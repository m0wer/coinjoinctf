"""Contract scripts against Bitcoin Core consensus + standardness (needs `docker compose up -d`)."""

import os

import pytest
from bitcointx.wallet import CCoinKey

from coinjoinctf import contract as ct
from coinjoinctf.chain import Coin, fund, new_tx, p2tr_key, set_witness
from coinjoinctf.rpc import RPC, RPCError, mine, node

pytestmark = pytest.mark.regtest
N, M = 128, 3


@pytest.fixture(scope="module")
def rpc() -> RPC:
    try:
        return node()
    except (RPCError, OSError):
        pytest.skip("regtest node not running")


class Setup:
    def __init__(self, rpc: RPC) -> None:
        self.rpc = rpc
        self.host, self.part = (
            CCoinKey.from_secret_bytes(os.urandom(32)),
            CCoinKey.from_secret_bytes(os.urandom(32)),
        )
        self.lamport = ct.Lamport.generate(N)
        self.labels = [[(os.urandom(16), os.urandom(16)) for _ in range(N)] for _ in range(M)]
        self.win_labels = [os.urandom(16) for _ in range(M)]
        self.terms = ct.ContractTerms(
            host_pk=bytes(self.host.xonly_pub),
            part_pk=bytes(self.part.xonly_pub),
            lamport=self.lamport.hashes,
            label_hashes=[tuple((ct.sha(a), ct.sha(b)) for a, b in inst) for inst in self.labels],
            win_hashes=[ct.sha(w) for w in self.win_labels],
            abort_csv=3,
            timeout_csv=3,
            settle_csv=3,
        )
        self.bits = [b & 1 for b in os.urandom(N)]

    def coin(self, tree) -> Coin:  # type: ignore[no-untyped-def]
        spk = ct.tree_spk(tree)
        _, (c,) = fund(self.rpc, [(100_000, spk)])
        return c

    def accept(self, tx) -> tuple[bool, str]:  # type: ignore[no-untyped-def]
        r = self.rpc.testmempoolaccept([tx.serialize().hex()])[0]
        return r["allowed"], r.get("reject-reason", "")

    def assert_tx(self, preimages: list[bytes], redirect: bool = False):  # type: ignore[no-untyped-def]
        c = self.coin(self.terms.contract_tree())
        s, cb = ct.leaf(self.terms.contract_tree(), "assert")
        tx = new_tx([c], [(c.value - 20_000, ct.tree_spk(self.terms.asserted_tree()))])
        sh = s.sighash_schnorr(tx, 0, [c.txout()])
        sigs = self.part.sign_schnorr_no_tweak(sh), self.host.sign_schnorr_no_tweak(sh)
        if redirect:  # participant reuses the host presig on a tx paying itself
            tx = new_tx([c], [(c.value - 20_000, bytes(p2tr_key(self.part)))])
            sigs = self.part.sign_schnorr_no_tweak(s.sighash_schnorr(tx, 0, [c.txout()])), sigs[1]
        set_witness(tx, 0, ct.assert_witness(preimages, *sigs, s, cb))
        return tx

    def deliver_tx(self, preimages: list[bytes], labels: list[list[bytes]]):  # type: ignore[no-untyped-def]
        c = self.coin(self.terms.asserted_tree())
        s, cb = ct.leaf(self.terms.asserted_tree(), "deliver")
        tx = new_tx([c], [(c.value - 30_000, bytes(p2tr_key(self.host)))])
        sh = s.sighash_schnorr(tx, 0, [c.txout()])
        sigs = self.part.sign_schnorr_no_tweak(sh), self.host.sign_schnorr_no_tweak(sh)
        set_witness(tx, 0, ct.deliver_witness(preimages, labels, *sigs, s, cb))
        return tx

    def honest_labels(self) -> list[list[bytes]]:
        return [[inst[i][self.bits[i]] for i in range(N)] for inst in self.labels]


@pytest.fixture
def s(rpc: RPC) -> Setup:
    return Setup(rpc)


def test_assert_accepts_lamport_commitment(s: Setup) -> None:
    assert s.accept(s.assert_tx(s.lamport.reveal(s.bits))) == (True, "")


def test_assert_cannot_redirect_funds(s: Setup) -> None:
    allowed, reason = s.accept(s.assert_tx(s.lamport.reveal(s.bits), redirect=True))
    assert not allowed and "Invalid Schnorr signature" in reason


def test_assert_rejects_non_preimage(s: Setup) -> None:
    pre = s.lamport.reveal(s.bits)
    pre[7] = os.urandom(32)
    assert not s.accept(s.assert_tx(pre))[0]


def test_deliver_accepts_matching_labels(s: Setup) -> None:
    assert s.accept(s.deliver_tx(s.lamport.reveal(s.bits), s.honest_labels())) == (True, "")


def test_deliver_rejects_label_for_uncommitted_bit(s: Setup) -> None:
    labels = s.honest_labels()
    labels[1][42] = s.labels[1][42][1 - s.bits[42]]  # label of the other bit value
    assert not s.accept(s.deliver_tx(s.lamport.reveal(s.bits), labels))[0]


def test_deliver_rejects_garbage_label(s: Setup) -> None:
    labels = s.honest_labels()
    labels[0][0] = os.urandom(16)
    assert not s.accept(s.deliver_tx(s.lamport.reveal(s.bits), labels))[0]


def test_deliver_rejects_unknown_preimage(s: Setup) -> None:
    pre = s.lamport.reveal(s.bits)
    pre[3] = os.urandom(32)
    assert not s.accept(s.deliver_tx(pre, s.honest_labels()))[0]


@pytest.mark.parametrize(
    "leaf_name,tree_name,signer",
    [
        ("timeout", "asserted_tree", "part"),
        ("abort", "contract_tree", "host"),
    ],
)
def test_csv_paths(s: Setup, leaf_name: str, tree_name: str, signer: str) -> None:
    tree = getattr(s.terms, tree_name)()
    key = getattr(s, signer)
    c = s.coin(tree)
    script, cb = ct.leaf(tree, leaf_name)
    tx = new_tx([c], [(c.value - 1000, bytes(p2tr_key(key)))], sequence=3)
    set_witness(
        tx, 0, [key.sign_schnorr_no_tweak(script.sighash_schnorr(tx, 0, [c.txout()])), bytes(script), cb]
    )
    assert s.accept(tx) == (False, "non-BIP68-final")
    mine(s.rpc, 3)
    assert s.accept(tx) == (True, "")


def test_win_leaf_needs_the_committed_label(s: Setup) -> None:
    tree = s.terms.delivered_tree()
    for label, ok in [(os.urandom(16), False), (s.win_labels[2], True)]:
        c = s.coin(tree)
        script, cb = ct.leaf(tree, "win2")
        tx = new_tx([c], [(c.value - 1000, bytes(p2tr_key(s.part)))])
        sig = s.part.sign_schnorr_no_tweak(script.sighash_schnorr(tx, 0, [c.txout()]))
        set_witness(tx, 0, [label, sig, bytes(script), cb])
        assert s.accept(tx)[0] is ok


def test_stack_limit_guard() -> None:
    hashes = tuple((bytes(32), bytes(32)) for _ in range(N))
    ct.deliver_leaf(bytes(32), bytes(32), hashes, [hashes] * 6)  # 128 * 7 + 2 = 898
    with pytest.raises(ValueError, match="stack limit"):
        ct.deliver_leaf(bytes(32), bytes(32), hashes, [hashes] * 7)  # 1026
