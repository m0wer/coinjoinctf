"""Third-party audit of a finished entry, from the chain plus the host's published transcript.

The transcript holds no secret: opened seeds belong to discarded instances, and the retained
instances are published only as tables, label hashes and the host's input labels (one label per
wire, which hides the bit). Anyone can check that the participant signed the instance choice,
that every opened instance is an honest garbling, which guess the participant committed on-chain,
and what the retained instances output on the labels the deliver script forced. With the setup
proof, ``win = 0, o1 = 1`` proves the guess differs from a committed complete tip set, while the
set itself stays hidden.
"""

from __future__ import annotations

import base64
from math import comb
from typing import Any

from bitcointx.core.key import XOnlyPubKey
from pydantic import BaseModel

from coinjoinctf import contract as ct
from coinjoinctf.circuit import (
    HOST_WIRES,
    OUT_EQ,
    OUT_O1,
    OUT_WIN,
    X_BITS,
    bits_to_bytes,
    bytes_to_bits,
    game_circuit,
)
from coinjoinctf.game import GameManifest, Host, SetupVerifier, choice_message
from coinjoinctf.garble import EvaluationError, GarbledPublic, evaluate, verify_opened
from coinjoinctf.rpc import RPC


class Transcript(BaseModel):
    entry: str
    commitments: list[str]
    retained: list[int]
    choice_sig: str
    opened: dict[int, str]
    retained_publics: list[dict[str, Any]]
    host_labels: list[list[str]]
    host_pk: str
    part_pk: str
    lamport: list[tuple[str, str]]
    txids: dict[str, str]


def _pairs(pairs: tuple[tuple[bytes, bytes], ...]) -> list[list[str]]:
    return [[a.hex(), b.hex()] for a, b in pairs]


def _unpairs(pairs: list[list[str]]) -> tuple[tuple[bytes, bytes], ...]:
    return tuple((bytes.fromhex(a), bytes.fromhex(b)) for a, b in pairs)


def public_to_json(p: GarbledPublic) -> dict[str, Any]:
    return {
        "tables": base64.b64encode(p.tables).decode(),
        "x": _pairs(p.x_label_hashes),
        "host": _pairs(p.host_label_hashes),
        "out": _pairs(p.output_label_hashes),
    }


def public_from_json(d: dict[str, Any]) -> GarbledPublic:
    return GarbledPublic(
        base64.b64decode(d["tables"]), _unpairs(d["x"]), _unpairs(d["host"]), _unpairs(d["out"])
    )


def host_transcript(host: Host, entry: str) -> Transcript:
    st = host.entries[entry]
    assert st.terms is not None
    bits = bytes_to_bits(host.y + host.r)
    return Transcript(
        entry=entry,
        commitments=[g.public.commitment().hex() for g in st.garbled],
        retained=st.retained,
        choice_sig=st.choice_sig.hex(),
        opened={i: s.hex() for i, s in enumerate(st.seeds) if i not in st.retained},
        retained_publics=[public_to_json(st.garbled[j].public) for j in st.retained],
        host_labels=[
            [st.garbled[j].input_label(w, bits[n]).hex() for n, w in enumerate(HOST_WIRES)]
            for j in st.retained
        ],
        host_pk=st.terms.host_pk.hex(),
        part_pk=st.terms.part_pk.hex(),
        lamport=[(a.hex(), b.hex()) for a, b in st.terms.lamport],
        txids=dict(st.txids),
    )


class AuditError(Exception):
    pass


def _check(ok: bool, what: str) -> None:
    if not ok:
        raise AuditError(what)


def audit_entry(rpc: RPC, m: GameManifest, t: Transcript, verify_setup: SetupVerifier) -> dict[str, Any]:
    setup = verify_setup(m)
    circuit = game_circuit(bytes.fromhex(m.com))
    _check(circuit.fingerprint() == m.circuit_fingerprint, "circuit fingerprint")
    commitments = [bytes.fromhex(c) for c in t.commitments]
    _check(len(commitments) == m.n_instances and len(t.retained) == m.n_retained, "instance counts")
    _check(sorted(t.opened) == [i for i in range(m.n_instances) if i not in t.retained], "opened set")
    msg = choice_message(commitments, t.retained)
    _check(
        XOnlyPubKey(bytes.fromhex(t.part_pk)).verify_schnorr(msg, bytes.fromhex(t.choice_sig)),
        "choice signature",
    )
    for i, seed in t.opened.items():
        _check(
            verify_opened(circuit, bytes.fromhex(seed), commitments[i]), f"opened instance {i} is not honest"
        )
    publics = [public_from_json(d) for d in t.retained_publics]
    for j, p in zip(t.retained, publics, strict=True):
        _check(p.commitment() == commitments[j], f"retained instance {j} does not match its commitment")

    terms = ct.ContractTerms(
        host_pk=bytes.fromhex(t.host_pk), part_pk=bytes.fromhex(t.part_pk),
        lamport=tuple((bytes.fromhex(a), bytes.fromhex(b)) for a, b in t.lamport),
        label_hashes=[p.x_label_hashes for p in publics],
        win_hashes=[p.output_label_hashes[OUT_WIN][1] for p in publics],
        abort_csv=m.abort_csv, timeout_csv=m.timeout_csv, settle_csv=m.settle_csv,
    )  # fmt: skip
    fund = rpc.getrawtransaction(t.txids["fund"], True)
    _check(
        bytes.fromhex(fund["vout"][0]["scriptPubKey"]["hex"]) == ct.tree_spk(terms.contract_tree()),
        "fund output",
    )
    a = rpc.getrawtransaction(t.txids["assert"], True)
    _check((a["vin"][0]["txid"], a["vin"][0]["vout"]) == (t.txids["fund"], 0), "assert spends the contract")
    _check(
        bytes.fromhex(a["vout"][0]["scriptPubKey"]["hex"]) == ct.tree_spk(terms.asserted_tree()),
        "asserted output",
    )
    preimages = ct.parse_assert_witness([bytes.fromhex(x) for x in a["vin"][0]["txinwitness"]], X_BITS)
    guess_bits = ct.decode_bits(terms.lamport, preimages)
    d = rpc.getrawtransaction(t.txids["deliver"], True)
    _check(
        (d["vin"][0]["txid"], d["vin"][0]["vout"]) == (t.txids["assert"], 0), "deliver spends the assertion"
    )
    _check(
        bytes.fromhex(d["vout"][0]["scriptPubKey"]["hex"]) == ct.tree_spk(terms.delivered_tree()),
        "delivered output",
    )
    _, x_labels = ct.parse_deliver_witness(
        [bytes.fromhex(x) for x in d["vin"][0]["txinwitness"]], X_BITS, m.n_retained
    )

    instances: list[dict[str, Any]] = []
    for n, (j, p) in enumerate(zip(t.retained, publics, strict=True)):
        try:
            bits, _ = evaluate(circuit, p, x_labels[n], [bytes.fromhex(h) for h in t.host_labels[n]])
            instances.append({"instance": j, "win": bits[OUT_WIN], "eq": bits[OUT_EQ], "o1": bits[OUT_O1]})
        except EvaluationError as e:
            instances.append({"instance": j, "error": str(e)})
    if all(i.get("win") == 0 and i.get("o1") == 1 for i in instances):
        verdict = "lost: the guess differs from the committed complete tip set"
    elif any(i.get("win") == 1 for i in instances):
        verdict = "won: a retained instance released the winning label"
    else:
        verdict = "host misbehaved: inconsistent or invalid retained instances"
    return {
        "verdict": verdict,
        "guess": bits_to_bytes(guess_bits).hex(),
        "instances": instances,
        "opened_checked": len(t.opened),
        "cheat_probability": 1 / comb(m.n_instances, m.n_retained),
        "setup": setup,
    }
