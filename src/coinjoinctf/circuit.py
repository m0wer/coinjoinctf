"""Boolean circuits with constant folding, a SHA-256 compression gadget and the game circuit.

Gate set: XOR, AND, INV (free-XOR friendly). Wires 0..n_inputs-1 are inputs; every gate
appends one wire. Constants never reach the gate list: they are folded at build time.

Bit conventions: byte strings map to bits MSB-first per byte (bit i of ``data`` is
``(data[i // 8] >> (7 - i % 8)) & 1``). SHA-256 words are handled LSB-first internally.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

XOR, AND, INV = 0, 1, 2
ZERO, ONE = -1, -2  # constant pseudo-wires

# Game circuit layout (all sizes in bits).
X_BITS = 128  # participant guess: SHA256(canonical tip list)[:16]
Y_BITS = 128  # host answer, same encoding
R_BITS = 256  # host commitment randomness
N_INPUTS = X_BITS + Y_BITS + R_BITS
X_WIRES = range(0, X_BITS)
HOST_WIRES = range(X_BITS, N_INPUTS)  # y || r
# Outputs: win, eq, o1. The payout is a hashlock on the label of win = 1.
OUT_WIN, OUT_EQ, OUT_O1 = 0, 1, 2


@dataclass(frozen=True)
class Circuit:
    n_inputs: int
    n_wires: int
    gates: tuple[tuple[int, int, int, int], ...]  # (op, a, b, out); b == -1 for INV
    outputs: tuple[int, ...]

    @property
    def and_count(self) -> int:
        return sum(1 for g in self.gates if g[0] == AND)

    def fingerprint(self) -> str:
        h = hashlib.sha256()
        h.update(f"{self.n_inputs}:{self.n_wires}:".encode())
        for g in self.gates:
            h.update(bytes(f"{g[0]},{g[1]},{g[2]},{g[3]};", "ascii"))
        h.update(repr(self.outputs).encode())
        return h.hexdigest()


class Builder:
    def __init__(self, n_inputs: int) -> None:
        self.n_inputs = n_inputs
        self.next_wire = n_inputs
        self.gates: list[tuple[int, int, int, int]] = []
        self._inv_of: dict[int, int] = {}
        self._cache: dict[tuple[int, int, int], int] = {}

    def _emit(self, op: int, a: int, b: int) -> int:
        key = (op, min(a, b), max(a, b)) if op != INV else (op, a, -1)
        if key in self._cache:
            return self._cache[key]
        out = self.next_wire
        self.next_wire += 1
        self.gates.append((op, a, b, out))
        self._cache[key] = out
        return out

    def inv(self, a: int) -> int:
        if a == ZERO:
            return ONE
        if a == ONE:
            return ZERO
        if a in self._inv_of:
            return self._inv_of[a]
        out = self._emit(INV, a, -1)
        self._inv_of[out] = a
        return out

    def xor(self, a: int, b: int) -> int:
        if a == b:
            return ZERO
        if a == ZERO:
            return b
        if b == ZERO:
            return a
        if a == ONE:
            return self.inv(b)
        if b == ONE:
            return self.inv(a)
        if self._inv_of.get(a) == b or self._inv_of.get(b) == a:
            return ONE
        return self._emit(XOR, a, b)

    def and_(self, a: int, b: int) -> int:
        if ZERO in (a, b):
            return ZERO
        if a == ONE:
            return b
        if b == ONE or a == b:
            return a
        if self._inv_of.get(a) == b or self._inv_of.get(b) == a:
            return ZERO
        return self._emit(AND, a, b)

    def or_(self, a: int, b: int) -> int:
        return self.inv(self.and_(self.inv(a), self.inv(b)))

    def all_(self, bits: list[int]) -> int:
        layer = list(bits)
        while len(layer) > 1:
            nxt = [self.and_(layer[i], layer[i + 1]) for i in range(0, len(layer) - 1, 2)]
            if len(layer) % 2:
                nxt.append(layer[-1])
            layer = nxt
        return layer[0]

    def eq_const(self, bits: list[int], value: bytes) -> int:
        return self.all_([b if c else self.inv(b) for b, c in zip(bits, bytes_to_bits(value), strict=True)])

    def build(self, outputs: list[int]) -> Circuit:
        if any(o < 0 for o in outputs):
            raise ValueError("constant output wire; circuit is degenerate")
        return Circuit(self.n_inputs, self.next_wire, tuple(self.gates), tuple(outputs))


def bytes_to_bits(data: bytes) -> list[int]:
    return [(data[i // 8] >> (7 - i % 8)) & 1 for i in range(len(data) * 8)]


def bits_to_bytes(bits: list[int]) -> bytes:
    out = bytearray(len(bits) // 8)
    for i, bit in enumerate(bits):
        out[i // 8] |= bit << (7 - i % 8)
    return bytes(out)


# --- SHA-256 -----------------------------------------------------------------------

Word = list[int]  # 32 wires, LSB first

_K = [
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4,
    0xAB1C5ED5, 0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE,
    0x9BDC06A7, 0xC19BF174, 0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F,
    0x4A7484AA, 0x5CB0A9DC, 0x76F988DA, 0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
    0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967, 0x27B70A85, 0x2E1B2138, 0x4D2C6DFC,
    0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85, 0xA2BFE8A1, 0xA81A664B,
    0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070, 0x19A4C116,
    0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7,
    0xC67178F2,
]  # fmt: skip
_IV = [
    0x6A09E667,
    0xBB67AE85,
    0x3C6EF372,
    0xA54FF53A,
    0x510E527F,
    0x9B05688C,
    0x1F83D9AB,
    0x5BE0CD19,
]


def _const_word(v: int) -> Word:
    return [ONE if (v >> i) & 1 else ZERO for i in range(32)]


def _rotr(w: Word, n: int) -> Word:
    return [w[(i + n) % 32] for i in range(32)]


def _shr(w: Word, n: int) -> Word:
    return [w[i + n] if i + n < 32 else ZERO for i in range(32)]


def _xor3(b: Builder, x: Word, y: Word, z: Word) -> Word:
    return [b.xor(b.xor(x[i], y[i]), z[i]) for i in range(32)]


def _add(b: Builder, x: Word, y: Word) -> Word:
    out: Word = []
    carry = ZERO
    for i in range(32):
        out.append(b.xor(b.xor(x[i], y[i]), carry))
        if i < 31:  # carry = maj(x, y, carry) with one AND
            carry = b.xor(b.and_(b.xor(x[i], carry), b.xor(y[i], carry)), carry)
    return out


def sha256_compress(b: Builder, state: list[Word], block: list[Word]) -> list[Word]:
    w = list(block)
    for t in range(16, 64):
        s0 = _xor3(b, _rotr(w[t - 15], 7), _rotr(w[t - 15], 18), _shr(w[t - 15], 3))
        s1 = _xor3(b, _rotr(w[t - 2], 17), _rotr(w[t - 2], 19), _shr(w[t - 2], 10))
        w.append(_add(b, _add(b, s1, w[t - 7]), _add(b, s0, w[t - 16])))
    a, bb, c, d, e, f, g, h = state
    for t in range(64):
        big_s1 = _xor3(b, _rotr(e, 6), _rotr(e, 11), _rotr(e, 25))
        ch = [b.xor(b.and_(e[i], b.xor(f[i], g[i])), g[i]) for i in range(32)]
        t1 = _add(b, _add(b, _add(b, h, big_s1), _add(b, ch, _const_word(_K[t]))), w[t])
        big_s0 = _xor3(b, _rotr(a, 2), _rotr(a, 13), _rotr(a, 22))
        maj = [b.xor(b.and_(b.xor(a[i], bb[i]), b.xor(a[i], c[i])), a[i]) for i in range(32)]
        t2 = _add(b, big_s0, maj)
        h, g, f, e, d, c, bb, a = g, f, e, _add(b, d, t1), c, bb, a, _add(b, t1, t2)
    return [_add(b, s, v) for s, v in zip(state, [a, bb, c, d, e, f, g, h], strict=True)]


def _bits_to_words(bits: list[int]) -> list[Word]:
    """MSB-first byte bits (big-endian words) -> LSB-first words."""
    words = []
    for m in range(len(bits) // 32):
        words.append([bits[(4 * m + 3 - j // 8) * 8 + 7 - j % 8] for j in range(32)])
    return words


def _words_to_bits(words: list[Word]) -> list[int]:
    return [words[d // 32][31 - d % 32] for d in range(len(words) * 32)]


def sha256_single_block(b: Builder, msg_bits: list[int]) -> list[int]:
    """Full SHA-256 (with padding) of a message of at most 55 bytes; returns 256 digest bits."""
    n = len(msg_bits)
    if n % 8 or n > 55 * 8:
        raise ValueError("message must be whole bytes and fit one block")
    pad = bytes_to_bits(b"\x80" + b"\x00" * (55 - n // 8) + (n).to_bytes(8, "big"))
    block = msg_bits + [ONE if p else ZERO for p in pad]
    digest = sha256_compress(b, [_const_word(v) for v in _IV], _bits_to_words(block))
    return _words_to_bits(digest)


# --- Game circuit --------------------------------------------------------------------


def game_circuit(com: bytes) -> Circuit:
    """win = (x == y) OR (SHA256(y || r) != com); also reveals eq and o1.

    o1 = [SHA256(y || r) == com]: if the host feeds anything but the committed answer,
    win = 1 for every guess, so the host cannot dodge a correct guess by lying about y.
    """
    b = Builder(N_INPUTS)
    x = list(X_WIRES)
    y = list(range(X_BITS, X_BITS + Y_BITS))
    r = list(range(X_BITS + Y_BITS, N_INPUTS))
    o1 = b.eq_const(sha256_single_block(b, y + r), com)
    eq = b.all_([b.inv(b.xor(xi, yi)) for xi, yi in zip(x, y, strict=True)])
    win = b.or_(eq, b.inv(o1))
    return b.build([win, eq, o1])


def answer_commitment(y: bytes, r: bytes) -> bytes:
    return hashlib.sha256(y + r).digest()


def game_inputs(x: bytes, y: bytes, r: bytes) -> list[int]:
    assert len(x) * 8 == X_BITS and len(y) * 8 == Y_BITS and len(r) * 8 == R_BITS
    return bytes_to_bits(x + y + r)


def evaluate_plain(c: Circuit, inputs: list[int]) -> list[int]:
    if len(inputs) != c.n_inputs:
        raise ValueError("wrong input length")
    v = list(inputs) + [0] * (c.n_wires - c.n_inputs)
    for op, a, bb, out in c.gates:
        if op == XOR:
            v[out] = v[a] ^ v[bb]
        elif op == AND:
            v[out] = v[a] & v[bb]
        else:
            v[out] = v[a] ^ 1
    return [v[o] for o in c.outputs]
