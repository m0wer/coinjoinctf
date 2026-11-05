import hashlib
import itertools
import os

import pytest

from coinjoinctf.circuit import (
    HOST_WIRES,
    X_WIRES,
    Builder,
    answer_commitment,
    bits_to_bytes,
    bytes_to_bits,
    evaluate_plain,
    game_circuit,
    game_inputs,
    sha256_single_block,
)
from coinjoinctf.garble import (
    EvaluationError,
    GarbledPublic,
    evaluate,
    evaluate_labels,
    garble,
    label_hash,
    verify_opened,
)


@pytest.mark.parametrize("n", [1, 16, 31, 48, 55])
def test_sha256_gadget_matches_hashlib(n: int) -> None:
    b = Builder(n * 8)
    c = b.build(sha256_single_block(b, list(range(n * 8))))
    msg = os.urandom(n)
    assert bits_to_bytes(evaluate_plain(c, bytes_to_bits(msg))) == hashlib.sha256(msg).digest()


@pytest.fixture(scope="module")
def game() -> tuple:
    y, r = os.urandom(16), os.urandom(32)
    return game_circuit(answer_commitment(y, r)), y, r


def test_game_circuit_semantics(game: tuple) -> None:
    c, y, r = game
    assert evaluate_plain(c, game_inputs(y, y, r)) == [1, 1, 1]  # win, eq, o1
    assert evaluate_plain(c, game_inputs(os.urandom(16), y, r)) == [0, 0, 1]
    # Host feeds an uncommitted answer (or randomness): every guess wins.
    assert evaluate_plain(c, game_inputs(os.urandom(16), os.urandom(16), r)) == [1, 0, 0]
    assert evaluate_plain(c, game_inputs(y, y, os.urandom(32))) == [1, 1, 0]


def _labels(g, x: bytes, host: bytes) -> tuple[list[bytes], list[bytes]]:  # type: ignore[no-untyped-def]
    xb, hb = bytes_to_bits(x), bytes_to_bits(host)
    return (
        [g.input_label(w, xb[i]) for i, w in enumerate(X_WIRES)],
        [g.input_label(w, hb[i]) for i, w in enumerate(HOST_WIRES)],
    )


def test_garbled_evaluation_matches_plain(game: tuple) -> None:
    c, y, r = game
    g = garble(c, os.urandom(32))
    for x in (y, os.urandom(16)):
        xl, hl = _labels(g, x, y + r)
        bits, labels = evaluate(c, g.public, xl, hl)
        assert bits == evaluate_plain(c, game_inputs(x, y, r))
        assert label_hash(labels[0]) == g.public.output_label_hashes[0][bits[0]]


def test_half_gates_exhaustive() -> None:
    b = Builder(2)
    c = b.build([b.and_(0, 1), b.xor(0, 1), b.inv(b.and_(b.inv(0), 1)), b.and_(b.xor(0, 1), 1)])
    for _ in range(20):
        g = garble(c, os.urandom(32), x_wires=range(0, 1), host_wires=range(1, 2))
        for va, vb in itertools.product((0, 1), repeat=2):
            out = evaluate_labels(c, g.public.tables, [g.input_label(0, va), g.input_label(1, vb)])
            decoded = [g.public.output_label_hashes[i].index(label_hash(o)) for i, o in enumerate(out)]
            assert decoded == evaluate_plain(c, [va, vb])


def test_cut_and_choose_detects_tampering(game: tuple) -> None:
    c, y, r = game
    g = garble(c, os.urandom(32))
    com = g.public.commitment()
    assert verify_opened(c, g.seed, com)
    assert not verify_opened(c, os.urandom(32), com)
    bad = GarbledPublic(
        tables=bytes([g.public.tables[0] ^ 1]) + g.public.tables[1:],
        x_label_hashes=g.public.x_label_hashes,
        host_label_hashes=g.public.host_label_hashes,
        output_label_hashes=g.public.output_label_hashes,
    )
    assert bad.commitment() != com


def test_uncommitted_labels_rejected(game: tuple) -> None:
    c, y, r = game
    g = garble(c, os.urandom(32))
    xl, hl = _labels(g, y, y + r)
    with pytest.raises(EvaluationError):
        evaluate(c, g.public, xl, [os.urandom(16)] + hl[1:])
    with pytest.raises(EvaluationError):
        evaluate(c, g.public, [os.urandom(16)] + xl[1:], hl)
