"""Privacy-preserving garbling: free-XOR + half-gates + point-and-permute (Zahur-Rosulek-Evans 2015).

The evaluator never sees a plaintext wire value except the decoded outputs. Each instance is
derived deterministically from a 32-byte seed so that opened instances can be re-garbled and
checked against the commitment the host published *before* the participant chose them.

Hash: H(L, j) = SHA256(L || j)[:16], modeled as a random oracle (circular correlation robust).
Labels are 16-byte strings; script commitments to labels are SHA256(label).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from coinjoinctf.circuit import HOST_WIRES, INV, X_WIRES, XOR, Circuit

LABEL_BYTES = 16
_MASK = (1 << 128) - 1


def _h(label: int, tweak: int) -> int:
    d = hashlib.sha256(label.to_bytes(16, "little") + tweak.to_bytes(8, "little")).digest()
    return int.from_bytes(d[:16], "little")


def label_bytes(label: int) -> bytes:
    return label.to_bytes(LABEL_BYTES, "little")


def label_hash(label: bytes) -> bytes:
    return hashlib.sha256(label).digest()


@dataclass(frozen=True)
class GarbledPublic:
    """Everything the evaluator may see about an instance (and what the host commits to)."""

    tables: bytes  # 32 bytes per AND gate: TG || TE
    x_label_hashes: tuple[tuple[bytes, bytes], ...]  # [i][b] = SHA256(L_i^b), participant wires
    host_label_hashes: tuple[tuple[bytes, bytes], ...]  # sorted pair per host wire (hides the bit)
    output_label_hashes: tuple[tuple[bytes, bytes], ...]  # [o][b] = SHA256(L_o^b)

    def commitment(self) -> bytes:
        h = hashlib.sha256(b"coinjoinctf/instance/v1")
        h.update(hashlib.sha256(self.tables).digest())
        for group in (self.x_label_hashes, self.host_label_hashes, self.output_label_hashes):
            h.update(len(group).to_bytes(4, "little"))
            for a, b in group:
                h.update(a + b)
        return h.digest()


@dataclass(frozen=True)
class GarbledSecret:
    """Host-only view of an instance. Never serialize ``delta`` or zero-labels publicly."""

    seed: bytes
    delta: int
    input_zero: tuple[int, ...]
    public: GarbledPublic

    def input_label(self, wire: int, bit: int) -> bytes:
        return label_bytes(self.input_zero[wire] ^ (self.delta if bit else 0))


def garble(
    c: Circuit,
    seed: bytes,
    x_wires: range = X_WIRES,
    host_wires: range = HOST_WIRES,
) -> GarbledSecret:
    """Garble ``c``. ``x_wires`` are evaluator inputs, ``host_wires`` garbler inputs."""
    if len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    stream = hashlib.shake_256(b"coinjoinctf/garble/v1" + seed).digest(16 * (c.n_inputs + 1))
    delta = int.from_bytes(stream[:16], "little") | 1  # lsb(delta) = 1 for point-and-permute
    w = [0] * c.n_wires
    for i in range(c.n_inputs):
        w[i] = int.from_bytes(stream[16 * (i + 1) : 16 * (i + 2)], "little")
    tables = bytearray()
    j = 0
    for op, a, b, out in c.gates:
        if op == XOR:
            w[out] = w[a] ^ w[b]
        elif op == INV:
            w[out] = w[a] ^ delta
        else:
            wa0, wb0 = w[a], w[b]
            pa, pb = wa0 & 1, wb0 & 1
            t0, t1 = 2 * j, 2 * j + 1
            ha0, ha1 = _h(wa0, t0), _h(wa0 ^ delta, t0)
            hb0, hb1 = _h(wb0, t1), _h(wb0 ^ delta, t1)
            tg = ha0 ^ ha1 ^ (delta if pb else 0)
            wg0 = ha0 ^ (tg if pa else 0)
            te = hb0 ^ hb1 ^ wa0
            we0 = hb0 ^ ((te ^ wa0) if pb else 0)
            w[out] = wg0 ^ we0
            tables += tg.to_bytes(16, "little") + te.to_bytes(16, "little")
            j += 1

    def pair(z: int) -> tuple[bytes, bytes]:
        return label_hash(label_bytes(z)), label_hash(label_bytes(z ^ delta))

    host_pairs = []
    for i in host_wires:
        h0, h1 = pair(w[i])
        host_pairs.append((min(h0, h1), max(h0, h1)))
    public = GarbledPublic(
        tables=bytes(tables),
        x_label_hashes=tuple(pair(w[i]) for i in x_wires),
        host_label_hashes=tuple(host_pairs),
        output_label_hashes=tuple(pair(w[o]) for o in c.outputs),
    )
    return GarbledSecret(seed=seed, delta=delta, input_zero=tuple(w[: c.n_inputs]), public=public)


def evaluate_labels(c: Circuit, tables: bytes, input_labels: list[bytes]) -> list[bytes]:
    """Generic garbled evaluation: one label per input wire in, one label per output out."""
    w = [0] * c.n_wires
    for i, lab in enumerate(input_labels):
        w[i] = int.from_bytes(lab, "little")
    j = 0
    for op, a, b, out in c.gates:
        if op == XOR:
            w[out] = w[a] ^ w[b]
        elif op == INV:
            w[out] = w[a]
        else:
            wa, wb = w[a], w[b]
            off = 32 * j
            tg = int.from_bytes(tables[off : off + 16], "little")
            te = int.from_bytes(tables[off + 16 : off + 32], "little")
            wg = _h(wa, 2 * j) ^ (tg if wa & 1 else 0)
            we = _h(wb, 2 * j + 1) ^ ((te ^ wa) if wb & 1 else 0)
            w[out] = wg ^ we
            j += 1
    return [label_bytes(w[o]) for o in c.outputs]


class EvaluationError(Exception):
    """Raised when delivered labels do not match commitments (provable host misbehavior)."""


def evaluate(
    c: Circuit, public: GarbledPublic, x_labels: list[bytes], host_labels: list[bytes]
) -> tuple[list[int], list[bytes]]:
    """Evaluate with one label per input wire; returns decoded output bits and output labels."""
    if len(x_labels) != len(X_WIRES) or len(host_labels) != len(HOST_WIRES):
        raise EvaluationError("wrong number of input labels")
    for i, lab in enumerate(x_labels):
        if label_hash(lab) not in public.x_label_hashes[i]:
            raise EvaluationError(f"participant-wire label {i} not committed")
    for i, lab in enumerate(host_labels):
        if label_hash(lab) not in public.host_label_hashes[i]:
            raise EvaluationError(f"host-wire label {i} not committed")
    out_labels = evaluate_labels(c, public.tables, x_labels + host_labels)
    bits = []
    for idx, lab in enumerate(out_labels):
        h = label_hash(lab)
        h0, h1 = public.output_label_hashes[idx]
        if h == h0:
            bits.append(0)
        elif h == h1:
            bits.append(1)
        else:
            raise EvaluationError(f"output {idx} decodes to neither committed label")
    return bits, out_labels


def verify_opened(c: Circuit, seed: bytes, commitment: bytes) -> bool:
    """Cut-and-choose check: re-garble from the revealed seed and compare commitments."""
    return garble(c, seed).public.commitment() == commitment


def commitment_root(commitments: list[bytes]) -> bytes:
    return hashlib.sha256(b"coinjoinctf/root/v1" + b"".join(commitments)).digest()
