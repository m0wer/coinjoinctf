//! Setup proof for the CoinJoin CTF (RISC Zero guest).
//!
//! Private input: wallet seed, commitment randomness r, and the raw blocks [start, end].
//! Statement: the blocks form a hash chain whose transactions match their merkle roots; the
//! committed wallet (keys SHA256(tag || seed || i), i < key_limit, as P2WPKH) owns U0, which is
//! created in range; the lineage is U0 plus every owned output of a transaction spending a lineage
//! output; the tips T are the lineage outputs unspent at `end`; and com = SHA256(y || r) with
//! y = SHA256(sorted "txid:vout" lines of T joined by "\n")[:16].
//! Public journal (176 bytes): SHA256(seed) | key_limit | u0 txid | u0 vout | start hash |
//! end hash | n_blocks | |T| | com. Integers are little-endian; hashes in internal byte order.
//! Mirrors coinjoinctf.stage.owned_tips, which is the reference implementation.

use std::collections::HashSet;
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
    outputs: Vec<Vec<u8>>, // scriptPubKeys
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
        r.take(8);
        let len = r.varint();
        outputs.push(r.take(len).to_vec());
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
    let mut lineage: HashSet<OutPoint> = HashSet::new();
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
            let mut hit = false;
            for i in &tx.inputs {
                if lineage.contains(i) {
                    spent.insert(*i);
                    hit = true;
                }
            }
            for (n, spk) in tx.outputs.iter().enumerate() {
                let op = (tx.txid, n as u32);
                if op == u0 {
                    assert!(
                        owned.contains(spk),
                        "U0 is not owned by the committed wallet"
                    );
                    lineage.insert(op);
                } else if hit && owned.contains(spk) {
                    lineage.insert(op);
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
        lineage.contains(&u0),
        "U0 is not created in the block range"
    );

    let mut tips: Vec<String> = lineage.difference(&spent).map(outpoint_str).collect();
    tips.sort();
    let y = &sha256(tips.join("\n").as_bytes())[..16];
    let com = sha256(&[y, &nonce[..]].concat());

    let mut journal = Vec::with_capacity(176);
    journal.extend(sha256(&seed));
    journal.extend(key_limit.to_le_bytes());
    journal.extend(u0.0);
    journal.extend(u0.1.to_le_bytes());
    journal.extend(first);
    journal.extend(prev.unwrap());
    journal.extend(n_blocks.to_le_bytes());
    journal.extend((tips.len() as u32).to_le_bytes());
    journal.extend(com);
    env::commit_slice(&journal);
}
