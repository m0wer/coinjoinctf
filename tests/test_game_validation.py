"""Hostile peer messages must be rejected before any stake or signature is released."""

from dataclasses import replace
from unittest.mock import Mock

import pytest
from bitcointx.core import CMutableTxOut
from bitcointx.core.script import CScript

from coinjoinctf import contract as ct
from coinjoinctf.chain import Coin, new_tx, p2tr_key
from coinjoinctf.game import FUND_FEE_SHARE, History, Host, Participant, choice_message


@pytest.fixture
def entry() -> tuple[Host, Participant]:
    history = History(
        u0="11" * 32 + ":0",
        start_height=1,
        end_height=1,
        start_hash="",
        end_hash="",
        wallet_commitment="",
        key_limit=1,
    )
    host = Host(Mock(), history, [history.u0], n_instances=4, n_retained=1)
    player = Participant(host.rpc, host.manifest(None), lambda _: {}, "test")
    player.choose(host.offer(player.name))
    player.verify(*host.open(player.name, player.retained, player.pk, player.choice_signature()))
    return host, player


def templates(host: Host, player: Participant) -> tuple:
    terms = player.terms(host.pk)
    pc = Coin("22" * 32, 0, player.m.entry_fee + FUND_FEE_SHARE, bytes(p2tr_key(player.key)))
    hc = Coin("33" * 32, 0, player.m.bounty + FUND_FEE_SHARE, bytes(p2tr_key(host.key)))
    funding = new_tx([pc, hc], [(player.m.entry_fee + player.m.bounty, ct.tree_spk(terms.contract_tree()))])
    coin = Coin(
        bytes(funding.GetTxid())[::-1].hex(), 0, funding.vout[0].nValue, bytes(funding.vout[0].scriptPubKey)
    )
    atx, dtx, presig = player.prepare(coin)
    return terms, coin, atx, dtx, presig, funding, [pc, hc]


def test_choice_is_immutable_and_identical_retry_is_safe(entry: tuple) -> None:
    host, p = entry
    before = host.open(p.name, p.retained, p.pk, p.choice_signature())
    assert before == host.open(p.name, list(p.retained), p.pk, p.choice_signature())
    other = [next(i for i in range(p.m.n_instances) if i not in p.retained)]
    sig = p.key.sign_schnorr_no_tweak(choice_message(p.commitments, other))
    with pytest.raises(ValueError, match="already fixed"):
        host.open(p.name, other, p.pk, sig)
    assert host.entries[p.name].retained == p.retained
    assert not set(before[0]) & set(p.retained)
    with pytest.raises(ValueError, match="already offered"):
        host.offer(p.name)


@pytest.mark.parametrize("indices", [[-1], [4], [0, 0]])
def test_invalid_choices_do_not_change_state(entry: tuple, indices: list[int]) -> None:
    host, p = entry
    with pytest.raises(ValueError):
        host.open(p.name, indices, p.pk, b"")
    assert host.entries[p.name].retained == p.retained


def test_other_participant_cannot_reopen(entry: tuple) -> None:
    host, p = entry
    other = Participant(host.rpc, p.m, lambda _: {}, "other")
    sig = other.key.sign_schnorr_no_tweak(choice_message(p.commitments, p.retained))
    with pytest.raises(ValueError, match="already fixed"):
        host.open(p.name, p.retained, other.pk, sig)


@pytest.mark.parametrize("transition", ["assert", "deliver"])
@pytest.mark.parametrize("mutation", ["extra-output", "amount", "input", "sequence", "locktime"])
def test_reject_modified_transitions(entry: tuple, transition: str, mutation: str) -> None:
    host, p = entry
    terms, coin, atx, dtx, presig, _, _ = templates(host, p)
    tx = atx if transition == "assert" else dtx
    if mutation == "extra-output":
        tx.vout[0].nValue -= 1000
        tx.vout.append(CMutableTxOut(1000, CScript(p2tr_key(p.key))))
    elif mutation == "amount":
        tx.vout[0].nValue = 1000
    elif mutation == "input":
        tx.vin[0].prevout.n = 1
    elif mutation == "sequence":
        tx.vin[0].nSequence = 0
    else:
        tx.nLockTime = 1
    # Even a valid peer signature must not authorize an unexpected delivery template.
    if transition == "deliver":
        asserted = Coin(
            bytes(atx.GetTxid())[::-1].hex(), 0, atx.vout[0].nValue, ct.tree_spk(terms.asserted_tree())
        )
        script, _ = ct.leaf(terms.asserted_tree(), "deliver")
        presig = p.key.sign_schnorr_no_tweak(script.sighash_schnorr(dtx, 0, [asserted.txout()]))
    with pytest.raises(ValueError, match=f"{transition} transaction differs"):
        host.accept_terms(p.name, terms, atx, coin, dtx, presig)
    assert host.entries[p.name].terms is None


@pytest.mark.parametrize("kind", ["empty", "short", "long", "equal", "hash-size", "label-width"])
def test_host_rejects_malformed_terms_before_signing(entry: tuple, kind: str) -> None:
    host, p = entry
    terms, coin, atx, dtx, presig, _, _ = templates(host, p)
    if kind == "empty":
        bad = replace(terms, lamport=())
    elif kind == "short":
        bad = replace(terms, lamport=terms.lamport[:-1])
    elif kind == "long":
        bad = replace(terms, lamport=terms.lamport + terms.lamport[:1])
    elif kind == "equal":
        bad = replace(terms, lamport=((terms.lamport[0][0],) * 2,) + terms.lamport[1:])
    elif kind == "hash-size":
        bad = replace(terms, lamport=((b"short", terms.lamport[0][1]),) + terms.lamport[1:])
    else:
        bad = replace(terms, label_hashes=[terms.label_hashes[0][:-1]])
    with pytest.raises(ValueError):
        host.accept_terms(p.name, bad, atx, coin, dtx, presig)
    assert host.entries[p.name].terms is None


def test_accepted_templates_are_private_snapshots(entry: tuple) -> None:
    host, p = entry
    terms, coin, atx, dtx, presig, funding, spent = templates(host, p)
    sig = host.accept_terms(p.name, terms, atx, coin, dtx, presig)
    p.check_host_presig(sig)
    expected_delivery = dtx.serialize()
    terms.win_hashes.clear()
    terms.label_hashes.clear()
    dtx.vout[0].nValue = 1000
    atx.vout[0].nValue = 1000
    st = host.entries[p.name]
    assert st.deliver_tx.serialize() == expected_delivery
    assert len(st.terms.win_hashes) == p.m.n_retained
    assert st.contract_coin.value == p.m.entry_fee + p.m.bounty
    assert p.assert_tx.vout[0].nValue != 1000
    p.sign_funding(funding, 0, spent)
    host.sign_funding(p.name, funding, 1, spent)


@pytest.mark.parametrize("signer", ["host", "participant"])
@pytest.mark.parametrize("mutation", ["redirect", "extra-output", "amount", "input"])
def test_funding_requires_the_complete_approved_template(entry: tuple, signer: str, mutation: str) -> None:
    host, p = entry
    terms, coin, atx, dtx, presig, funding, spent = templates(host, p)
    p.check_host_presig(host.accept_terms(p.name, terms, atx, coin, dtx, presig))
    if mutation == "redirect":
        funding.vout[0].scriptPubKey = p2tr_key(p.key)
    elif mutation == "extra-output":
        funding.vout.append(CMutableTxOut(1000, CScript(p2tr_key(p.key))))
    elif mutation == "amount":
        funding.vout[0].nValue -= 1000
    else:
        funding.vin[0].prevout.n = 1
    with pytest.raises(ValueError, match="funding transaction differs"):
        if signer == "host":
            host.sign_funding(p.name, funding, 1, spent)
        else:
            p.sign_funding(funding, 0, spent)


def test_accepted_terms_cannot_be_replaced(entry: tuple) -> None:
    host, p = entry
    terms, coin, atx, dtx, presig, _, _ = templates(host, p)
    host.accept_terms(p.name, terms, atx, coin, dtx, presig)
    with pytest.raises(ValueError, match="terms already accepted"):
        host.accept_terms(p.name, terms, atx, coin, dtx, presig)


def test_delivery_requires_the_approved_confirmed_assertion(entry: tuple) -> None:
    host, p = entry
    terms, coin, atx, dtx, presig, _, _ = templates(host, p)
    host.accept_terms(p.name, terms, atx, coin, dtx, presig)
    with pytest.raises(ValueError, match="unexpected assertion"):
        host.deliver(p.name, "44" * 32)
    host.rpc.getrawtransaction.assert_not_called()
    host.rpc.getrawtransaction.return_value = {"confirmations": 0}
    with pytest.raises(ValueError, match="must be confirmed"):
        host.deliver(p.name, bytes(atx.GetTxid())[::-1].hex())
