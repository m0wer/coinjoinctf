# coinjoinctf

A Bitcoin capture-the-flag for CoinJoin analysts. A host locks a bounty behind a trustless contract
and challenges anyone to follow one UTXO (U0) through a realistic JoinMarket history and name
**every** unspent output that descends from it. A correct guess claims the bounty unilaterally. A
wrong guess loses the entry fee, and anyone can verify that the guess was wrong and that a correct
answer existed, without learning the answer.

Hackathon proof of concept: regtest, a pure-Python garbler, RISC Zero for the setup proof.

## The challenge

The host withdraws U0 from an "exchange" and runs a simplified JoinMarket tumbler inside an
ecosystem of simulated makers (offers, real timelocked fidelity bonds, bond-weighted selection) and
random takers, block by block with random delays. Then the history is frozen at a block range.

The answer is the set of **tips**: starting from U0, follow every transaction that spends a lineage
output, add its outputs owned by the host wallet, and keep those still unspent at the end of the
range. Equal-amount coinjoin outputs, change and peel chains all count. A guess is encoded as
`SHA256("\n".join(sorted("txid:vout")))[:16]` (128 bits), so order does not matter and a subset or
a superset is simply wrong.

## How it works

Three mechanisms, each closing one way to cheat.

**1. Setup proof (RISC Zero): the committed answer is the real, complete tip set.**
The host commits `com = SHA256(y || r)` to the answer `y` and proves in the zkVM, without revealing
the wallet or the tips, that:

- the private raw blocks form a hash chain and every transaction matches its merkle root;
- the wallet with commitment `SHA256(seed)` (P2WPKH keys `SHA256("coinjoinctf/wallet/v1" || seed || i)`,
  `i < key_limit`) owns U0, which is created in the range;
- the tips are exactly the owned lineage outputs unspent at the end block, and `com` hashes them.

The public journal holds the wallet commitment, `key_limit`, U0, the first and last block hashes,
the block count, the number of tips and `com`. Every participant must verify the receipt before
entering, and anchors the block hashes to **its own node**.

**2. Garbled circuit per entry: the outcome is computed, not claimed.**
The circuit takes the participant's guess `x` and the host's `(y, r)` and outputs
`eq = (x == y)`, `o1 = (SHA256(y || r) == com)` and `win = eq OR NOT o1`. A host that garbles
with anything other than the committed answer makes `o1 = 0`, which hands the participant a win.
Per entry the host garbles 20 fresh instances (half-gates, free-XOR, 22,222 AND gates, 0.7 MB each)
and commits to them. The participant keeps 3 at random and signs that choice; the host opens the
other 17 and the participant re-garbles them to check honesty. Fresh circuits and an on-chain
commitment to the guess before any label is released mean nobody can test a guess offline.

**3. Taproot contract: the payout is enforced by Bitcoin Script.** Three outputs, NUMS internal
key (no keypath), every transition presigned by the party that would lose from a redirect:

| Output | Leaves |
|---|---|
| `O_contract` (entry fee + bounty) | `assert`: host presig + participant sig + one Lamport preimage per guess bit. `abort`: host after CSV (the participant never asserted). |
| `O_asserted` | `deliver`: participant presig + host sig + each bit's preimage and the matching participant-wire labels of the 3 kept instances, hash-checked per bit. `timeout`: participant after CSV (the host withheld labels). |
| `O_delivered` | `win_m`: participant sig + preimage of the `win = 1` output label of kept instance `m`. `settle`: host after CSV. |

The script only lets the host deliver labels for the bits already committed on-chain. The participant
evaluates the 3 kept instances with those labels and the host's own input labels. If any instance
outputs `win = 1`, its output label unlocks `win_m` and the participant claims everything.
Otherwise the host settles after the timelock.

**Public audit.** After an entry the host publishes a transcript: instance commitments, the signed
choice, opened seeds, kept tables, the host's input labels, the Lamport hashes and the txids.
Anyone can re-check the choice signature, re-garble the opened instances, read the guess from the
assert witness, read the labels from the deliver witness, re-evaluate the kept instances and
re-verify the setup proof. `win = 0, o1 = 1` on every kept instance proves the guess differs from a
committed complete tip set. The answer stays hidden: kept seeds are never revealed and each host
input label hides its bit.

## Trust model and known limits

- **Cut-and-choose soundness.** A host that garbles dishonestly survives the opening with
  probability `1 / C(20, 3) = 1/1140` per entry. A malformed kept instance shows up as an evaluation
  error, which the audit reports as host misbehavior.
- **Stalling does not help the host.** If it never delivers labels, `timeout` pays the participant
  the whole contract (entry fee and bounty).
- **The host can always win its own bounty.** It knows the answer and funds the game, so that only
  costs itself.
- **Serial entries.** A winning assert publishes the answer bits on-chain, so the game ends at the
  first win. Timing races (a late assert against the host's `abort` leaf) are not addressed;
  participants should assert promptly.
- **Ownership is part of the definition.** Only outputs of the committed wallet (`key_limit` keys,
  padded to a multiple of 16 to hide the exact address count) are tips; payments to anyone else end
  that branch. The proof covers the frozen block range only.
- **Out of band leaks are out of scope.** Anyone who learns the host's transactions directly (a
  colluding maker set, the host itself) can win.
- **Dev mode** (`--dev`) uses fake RISC Zero receipts for fast iteration; without `--dev`,
  participants reject them.
- **Demo shape.** Regtest only. Host and participant live in one process but only exchange protocol
  messages.

Measured on a 16-core CPU for a 36-block history (61 transactions, 579 outputs):

| | |
|---|---|
| Setup proof | 6.55M cycles, about 20 min, 9.6 GB RAM, 224 KB succinct receipt, 0.04 s to verify |
| Garbling | 0.16 s per instance (Python) |
| Assert / deliver tx | 3.6 kvB / 11.9 kvB (514 witness items; BIP342 allows 1000, so at most 6 kept instances) |

## Quick start

Requirements: Docker, [uv](https://docs.astral.sh/uv/), and the RISC Zero toolchain
([rzup](https://dev.risczero.com/api/zkvm/install)) to build the prover.

```sh
docker compose up -d                       # regtest node (tmpfs: a restart wipes the chain)
uv sync --extra dev
(cd zk && cargo build --release)           # zk/target/release/ctf-zk, a few minutes cold
uv run coinjoinctf --dev demo --fresh --makers 8 --takers 3
```

`demo` narrates the whole story in about 20 s: the JoinMarket stage, the setup proof, a near miss
(one tip swapped for an equal-valued sibling) that loses and is publicly audited, a correct guess
that wins and claims, and the optional reveal.

Step by step (state lives in `tmp/game`, host secrets in mode 0600 files):

```sh
uv run coinjoinctf stage --makers 12 --takers 4   # run the ecosystem, freeze the history
uv run coinjoinctf setup                          # host: commit + real setup proof (minutes)
uv run coinjoinctf play TXID:VOUT [TXID:VOUT ...] # participant: verify the proof, enter, play
uv run coinjoinctf audit entry1                   # anyone: audit a finished entry
uv run coinjoinctf reveal                         # host: optional disclosure after the game
```

`play --demo-guess correct|near_miss` lets the host pick the guess, and `--stall` simulates a host
that withholds labels.

## Web demo

```sh
uv run coinjoinctf --dev serve      # http://127.0.0.1:8000
```

The page grows the transaction graph live, block by block (one column per block, equal-amount
outputs colored per coinjoin, unspent outputs ringed). Click unspent outputs to build a guess, or
use the near miss and correct shortcuts. The protocol panel shows the 20 committed circuits (kept
vs. opened), the 128 asserted guess bits, each kept circuit's `win/eq/o1`, the outcome and the
public audit. Reveal draws the host's lineage in green.

For a talk with a real proof, prepare it beforehand and serve the same state; the page picks up the
frozen stage and the published game, so you start at step 3:

```sh
uv run coinjoinctf stage --makers 8 --takers 3 && uv run coinjoinctf setup
uv run coinjoinctf serve
```

Screencast (video and one screenshot per phase in `tmp/recording/`):

```sh
uv run --with playwright python -m playwright install chromium   # once
uv run --with playwright python demo/record.py
```

Terminal recording: `asciinema rec -c "uv run coinjoinctf --dev demo --fresh --makers 8 --takers 3 --pause 1.5" tmp/demo.cast`.

## Layout

| Path | What |
|---|---|
| `src/coinjoinctf/circuit.py` | Game circuit with a SHA-256 gadget and constant folding |
| `src/coinjoinctf/garble.py` | Half-gates garbler/evaluator, commitments, opened-instance checks |
| `src/coinjoinctf/contract.py` | Taproot leaves, Lamport commitments, witnesses |
| `src/coinjoinctf/game.py` | Host and participant roles, one entry end to end |
| `src/coinjoinctf/stage.py` | JoinMarket ecosystem, fidelity bonds, tumbler, reference tip oracle |
| `src/coinjoinctf/zk.py`, `zk/` | RISC Zero guest (the setup statement) and `ctf-zk prove/verify` |
| `src/coinjoinctf/audit.py` | Entry transcript and third-party audit |
| `src/coinjoinctf/session.py`, `cli.py`, `web.py`, `static/` | Orchestration, CLI, web demo |
| `demo/record.py` | Playwright screencast of the web demo |

## Tests

```sh
uv run pytest
```

Regtest tests skip without the node, and ZK tests skip without the built prover. ZK tests run the
guest for real in dev mode (only the seal is fake) and compare its journal with the Python oracle
`stage.owned_tips`.

## Authors and license

Adam Gibson (waxwing) and m0wer. Released under the [MIT License](LICENSE).
