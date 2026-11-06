//! Setup proof for the CoinJoin CTF (RISC Zero guest).
//!
//! Private input: wallet seed, commitment randomness r, and the raw blocks [start, end].
//! Statement: the blocks form a hash chain whose transactions match their merkle roots; the
//! committed wallet (keys SHA256(tag || seed || i), i < key_limit, as P2WPKH) owns U0, which is
//! created and spent in range; the lineage is U0 plus every owned output of a transaction spending
//! a lineage output; the tips T are the lineage outputs unspent at `end`, and T is not empty; and
//! com = SHA256(y || r) with y = SHA256(sorted "txid:vout" lines of T joined by "\n")[:16].
//! Disclosed structure, as minimums over T:
//!   tip_txs: distinct transactions creating T;
//!   min_depth: transactions on the shortest lineage path from U0;
//!   min_anonymity: distinct scriptPubKeys receiving the tip's exact value in its transaction;
//!   min_foreign_inputs: inputs that are not lineage outputs, over every lineage ancestor transaction.
//! Public journal (192 bytes): SHA256(seed) | key_limit | u0 txid | u0 vout | start hash |
//! end hash | n_blocks | |T| | com | tip_txs | min_depth | min_anonymity | min_foreign_inputs.
//! Integers are little-endian; hashes in internal byte order.
//! Mirrors coinjoinctf.stage.trace_lineage, which is the reference implementation.

use std::collections::{HashMap, HashSet};
use std::io::Read;

use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::SecretKey;
use ripemd::Ripemd160;
use risc0_zkvm::guest::env;
use sha2::{Digest, Sha256};

type Hash = [u8; 32];
type OutPoint = (Hash, u32);

fn sha256(data: &[u8]) -> Hash {
    Sha256::digest(data).into()
}

fn sha256d(data: &[u8]) -> Hash {
    sha256(&sha256(data))
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> &'a [u8] {
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        s
    }
    fn u32(&mut self) -> u32 {
        u32::from_le_bytes(self.take(4).try_into().unwrap())
    }
    fn hash(&mut self) -> Hash {
        self.take(32).try_into().unwrap()
    }
    fn varint(&mut self) -> usize {
        match self.take(1)[0] {
            0xfd => u16::from_le_bytes(self.take(2).try_into().unwrap()) as usize,
            0xfe => self.u32() as usize,
            0xff => u64::from_le_bytes(self.take(8).try_into().unwrap()) as usize,
            n => n as usize,
        }
    }
    fn done(&self) -> bool {
        self.pos == self.buf.len()
    }
}

struct Tx {
    txid: Hash,
    inputs: Vec<OutPoint>,
    outputs: Vec<(u64, Vec<u8>)>, // (value, scriptPubKey)
}

/// What the lineage knows about one of its outputs.
#[derive(Clone, Copy)]
struct Lineage {
    depth: u32,     // transactions on the shortest lineage path from U0
    foreign: u32,   // fewest non-lineage inputs of any lineage ancestor transaction
    anonymity: u32, // distinct scriptPubKeys receiving this exact value in the same transaction
}

fn anonymity(outputs: &[(u64, Vec<u8>)], value: u64) -> u32 {
    let same: HashSet<&[u8]> = outputs
        .iter()
        .filter(|(v, _)| *v == value)
        .map(|(_, spk)| spk.as_slice())
        .collect();
    same.len() as u32
}

/// Parse one transaction (legacy or BIP144 serialization). The txid covers non-witness data only.
fn parse_tx(r: &mut Reader) -> Tx {
    let version = r.take(4);
    let segwit = r.buf[r.pos] == 0;
    if segwit {
        assert_eq!(r.take(2)[1], 1, "bad segwit flag");
    }
    let body_start = r.pos;
    let n_in = r.varint();
    let mut inputs = Vec::with_capacity(n_in);
    for _ in 0..n_in {
        let txid = r.hash();
        let vout = r.u32();
        let len = r.varint();
        r.take(len + 4); // scriptSig, nSequence
        inputs.push((txid, vout));
    }
    let n_out = r.varint();
    let mut outputs = Vec::with_capacity(n_out);
    for _ in 0..n_out {
        let value = u64::from_le_bytes(r.take(8).try_into().unwrap());
        let len = r.varint();
        outputs.push((value, r.take(len).to_vec()));
    }
    let body_end = r.pos;
    if segwit {
        for _ in 0..n_in {
            for _ in 0..r.varint() {
                let len = r.varint();
                r.take(len);
            }
        }
    }
    let locktime = r.take(4);
    // Bitcoin hashes both txid leaves and pairs of child hashes with SHA256d. A 64-byte
    // stripped transaction can therefore masquerade as a Merkle internal node. This proof
    // deliberately excludes such histories; this is not a Bitcoin consensus validity rule.
    assert_ne!(
        version.len() + (body_end - body_start) + locktime.len(),
        64,
        "ambiguous 64-byte stripped transaction"
    );
    let mut h = Sha256::new();
    h.update(version);
    h.update(&r.buf[body_start..body_end]);
    h.update(locktime);
    Tx {
        txid: sha256(&h.finalize()),
        inputs,
        outputs,
    }
}

fn merkle_root(mut level: Vec<Hash>) -> Hash {
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            level.push(*level.last().unwrap());
        }
        level = level
            .chunks(2)
            .map(|p| sha256d(&[p[0], p[1]].concat()))
            .collect();
    }
    level[0]
}

/// P2WPKH scriptPubKeys of the committed wallet; invalid scalars are skipped, as in stage.wallet_key.
fn owned_spks(seed: &Hash, key_limit: u32) -> HashSet<Vec<u8>> {
    let mut set = HashSet::new();
    for i in 0..key_limit {
        let mut h = Sha256::new();
        h.update(b"coinjoinctf/wallet/v1");
        h.update(seed);
        h.update(i.to_le_bytes());
        let sk: Hash = h.finalize().into();
        let Ok(key) = SecretKey::from_slice(&sk) else {
            continue;
        };
        let pk = key.public_key().to_encoded_point(true);
        let mut spk = vec![0x00, 0x14];
        spk.extend_from_slice(&Ripemd160::digest(sha256(pk.as_bytes())));
        set.insert(spk);
    }
    set
}

fn outpoint_str((txid, vout): &OutPoint) -> String {
    let hex: String = txid.iter().rev().map(|b| format!("{b:02x}")).collect();
    format!("{hex}:{vout}")
}

fn main() {
    let mut input = Vec::new();
    env::stdin().read_to_end(&mut input).unwrap();
    let mut r = Reader {
        buf: &input,
        pos: 0,
    };
    let seed = r.hash();
    let nonce = r.hash();
    let key_limit = r.u32();
    let u0: OutPoint = (r.hash(), r.u32());
    let n_blocks = r.u32();
    assert!(n_blocks > 0 && key_limit > 0);

    let owned = owned_spks(&seed, key_limit);
    let mut lineage: HashMap<OutPoint, Lineage> = HashMap::new();
    let mut spent: HashSet<OutPoint> = HashSet::new();
    let (mut first, mut prev): (Hash, Option<Hash>) = ([0; 32], None);
    for _ in 0..n_blocks {
        let len = r.u32() as usize;
        let mut b = Reader {
            buf: r.take(len),
            pos: 0,
        };
        let header = b.take(80);
        let hash = sha256d(header);
        match prev {
            Some(p) => assert_eq!(&header[4..36], &p, "blocks do not form a chain"),
            None => first = hash,
        }
        prev = Some(hash);
        let n_tx = b.varint();
        let mut txids = Vec::with_capacity(n_tx);
        for _ in 0..n_tx {
            let tx = parse_tx(&mut b);
            // (shortest depth, fewest foreign inputs) over the lineage inputs, if any
            let mut parent: Option<(u32, u32)> = None;
            let mut foreign = 0u32;
            for i in &tx.inputs {
                match lineage.get(i) {
                    Some(l) => {
                        spent.insert(*i);
                        parent = Some(match parent {
                            Some((d, f)) => (d.min(l.depth), f.min(l.foreign)),
                            None => (l.depth, l.foreign),
                        });
                    }
                    None => foreign += 1,
                }
            }
            for (n, (value, spk)) in tx.outputs.iter().enumerate() {
                let op = (tx.txid, n as u32);
                if op == u0 {
                    assert!(
                        owned.contains(spk),
                        "U0 is not owned by the committed wallet"
                    );
                    // U0 must be spent, so it is never a tip and its anonymity is never read.
                    let start = Lineage {
                        depth: 0,
                        foreign: u32::MAX,
                        anonymity: 0,
                    };
                    lineage.insert(op, start);
                } else if let Some((depth, f)) = parent {
                    if owned.contains(spk) {
                        let next = Lineage {
                            depth: depth + 1,
                            foreign: f.min(foreign),
                            anonymity: anonymity(&tx.outputs, *value),
                        };
                        lineage.insert(op, next);
                    }
                }
            }
            txids.push(tx.txid);
        }
        assert!(b.done(), "trailing bytes in block");
        assert_eq!(
            txids.iter().collect::<HashSet<_>>().len(),
            txids.len(),
            "duplicate txid"
        );
        assert_eq!(
            &merkle_root(txids)[..],
            &header[36..68],
            "merkle root mismatch"
        );
    }
    assert!(r.done(), "trailing input");
    assert!(
        lineage.contains_key(&u0),
        "U0 is not created in the block range"
    );
    assert!(spent.contains(&u0), "U0 is never spent in the block range");

    // U0 is spent, so every tip was created by a lineage transaction (depth >= 1, finite foreign).
    let tips: Vec<(&OutPoint, &Lineage)> = lineage
        .iter()
        .filter(|(op, _)| !spent.contains(*op))
        .collect();
    assert!(!tips.is_empty(), "the lineage has no unspent tips");
    let tip_txs = tips
        .iter()
        .map(|(op, _)| op.0)
        .collect::<HashSet<_>>()
        .len() as u32;
    let min = |field: fn(&Lineage) -> u32| tips.iter().map(|(_, l)| field(l)).min().unwrap();
    let (min_depth, min_anonymity, min_foreign) =
        (min(|l| l.depth), min(|l| l.anonymity), min(|l| l.foreign));

    let mut names: Vec<String> = tips.iter().map(|(op, _)| outpoint_str(op)).collect();
    names.sort();
    let y = &sha256(names.join("\n").as_bytes())[..16];
    let com = sha256(&[y, &nonce[..]].concat());

    let mut journal = Vec::with_capacity(192);
    journal.extend(sha256(&seed));
    journal.extend(key_limit.to_le_bytes());
    journal.extend(u0.0);
    journal.extend(u0.1.to_le_bytes());
    journal.extend(first);
    journal.extend(prev.unwrap());
    journal.extend(n_blocks.to_le_bytes());
    journal.extend((tips.len() as u32).to_le_bytes());
    journal.extend(com);
    for stat in [tip_txs, min_depth, min_anonymity, min_foreign] {
        journal.extend(stat.to_le_bytes());
    }
    env::commit_slice(&journal);
}
