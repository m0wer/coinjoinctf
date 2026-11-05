//! ctf-zk: prove or verify the CoinJoin CTF setup statement (see methods/guest/src/main.rs).
//!
//!   ctf-zk prove <input.bin> <receipt.bin>   prints {"journal", "image_id", "cycles", "fake"}
//!   ctf-zk verify <receipt.bin>              prints {"journal", "image_id", "fake"}; exit 1 if invalid
//!   ctf-zk image-id
//!
//! RISC0_DEV_MODE=1 produces fake receipts for iteration; verifiers report them as "fake": true.

use methods::{LINEAGE_ELF, LINEAGE_ID};
use risc0_zkvm::{default_prover, ExecutorEnv, InnerReceipt, ProverOpts, Receipt};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn image_id() -> String {
    hex(&LINEAGE_ID
        .iter()
        .flat_map(|w| w.to_le_bytes())
        .collect::<Vec<u8>>())
}

fn fake(receipt: &Receipt) -> bool {
    matches!(receipt.inner, InnerReceipt::Fake(_))
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match (args.get(1).map(String::as_str), args.len()) {
        (Some("prove"), 4) => {
            let input = std::fs::read(&args[2]).expect("read input");
            let env = ExecutorEnv::builder()
                .write_slice(&input)
                .build()
                .expect("env");
            let info = default_prover()
                .prove_with_opts(env, LINEAGE_ELF, &ProverOpts::succinct())
                .expect("proving failed");
            info.receipt
                .verify(LINEAGE_ID)
                .expect("fresh receipt does not verify");
            std::fs::write(&args[3], bincode::serialize(&info.receipt).unwrap())
                .expect("write receipt");
            println!(
                "{{\"journal\":\"{}\",\"image_id\":\"{}\",\"cycles\":{},\"fake\":{}}}",
                hex(&info.receipt.journal.bytes),
                image_id(),
                info.stats.total_cycles,
                fake(&info.receipt)
            );
        }
        (Some("verify"), 3) => {
            let bytes = std::fs::read(&args[2]).expect("read receipt");
            let receipt: Receipt = bincode::deserialize(&bytes).expect("malformed receipt");
            if let Err(e) = receipt.verify(LINEAGE_ID) {
                eprintln!("invalid receipt: {e}");
                std::process::exit(1);
            }
            println!(
                "{{\"journal\":\"{}\",\"image_id\":\"{}\",\"fake\":{}}}",
                hex(&receipt.journal.bytes),
                image_id(),
                fake(&receipt)
            );
        }
        (Some("image-id"), 2) => println!("{}", image_id()),
        _ => {
            eprintln!(
                "usage: ctf-zk prove <input.bin> <receipt.bin> | verify <receipt.bin> | image-id"
            );
            std::process::exit(2);
        }
    }
}
