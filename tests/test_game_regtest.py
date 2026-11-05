"""Full entries on regtest: lose + audit, win + claim, host stall + timeout (stub setup verifier)."""

import os
from typing import Any

import pytest

from coinjoinctf.audit import AuditError, audit_entry, host_transcript
from coinjoinctf.game import GameManifest, History, Host, Participant, answer_hash, play_entry
from coinjoinctf.rpc import RPC, RPCError, node

pytestmark = pytest.mark.regtest
TIPS = [f"{i:064x}:{i % 3}" for i in range(1, 5)]


def stub_verifier(m: GameManifest) -> dict[str, Any]:
    return {"stub": True}


@pytest.fixture(scope="module")
def rpc() -> RPC:
    try:
        return node()
    except (RPCError, OSError):
        pytest.skip("regtest node not running")


@pytest.fixture(scope="module")
def host(rpc: RPC) -> Host:
    h = History(
        u0=TIPS[0],
        start_height=1,
        end_height=2,
        start_hash="",
        end_hash="",
        wallet_commitment="",
        key_limit=1,
    )
    return Host(rpc, h, TIPS)


def _play(
    host: Host, name: str, guess: list[str], **kw: Any
) -> tuple[dict[str, Any], list[tuple[str, dict]]]:
    events: list[tuple[str, dict]] = []
    p = Participant(host.rpc, host.manifest(None), stub_verifier, name)
    return play_entry(host, p, guess, lambda k, **d: events.append((k, d)), **kw), events


def test_wrong_guess_loses_and_audit_proves_it(rpc: RPC, host: Host) -> None:
    res, events = _play(host, "wrong", TIPS[:3])  # a subset is not the answer
    assert res["result"] == "lost"
    assert [k for k, _ in events][-2:] == ["evaluated", "settled"]
    m = host.manifest(None)
    t = host_transcript(host, "wrong")
    report = audit_entry(rpc, m, t, stub_verifier)
    assert report["verdict"].startswith("lost")
    assert report["guess"] == answer_hash(TIPS[:3]).hex()
    assert report["opened_checked"] == m.n_instances - m.n_retained
    # A tampered transcript is caught: forged choice, dishonest opened seed.
    # The host re-picks which instances count as retained (it knows every seed).
    st, new = host.entries["wrong"], max(t.opened)
    opened = {i: v for i, v in t.opened.items() if i != new} | {t.retained[0]: st.seeds[t.retained[0]].hex()}
    forged = t.model_copy(update={"retained": sorted([*t.retained[1:], new]), "opened": opened})
    with pytest.raises(AuditError, match="choice signature"):
        audit_entry(rpc, m, forged, stub_verifier)
    bad = dict(t.opened)
    bad[next(iter(bad))] = os.urandom(32).hex()
    with pytest.raises(AuditError, match="not honest"):
        audit_entry(rpc, m, t.model_copy(update={"opened": bad}), stub_verifier)


def test_right_guess_wins_and_claims(rpc: RPC, host: Host) -> None:
    res, events = _play(host, "right", list(reversed(TIPS)))  # order does not matter
    assert res["result"] == "won"
    claimed = dict(events)["claimed"]
    assert claimed["value"] > host.params["bounty"]  # entry fee + bounty, minus fees
    report = audit_entry(rpc, host.manifest(None), host_transcript(host, "right"), stub_verifier)
    assert report["verdict"].startswith("won")


def test_host_stall_lets_participant_reclaim(rpc: RPC, host: Host) -> None:
    res, _ = _play(host, "stall", TIPS, host_stalls=True)
    assert res["result"] == "timeout"
