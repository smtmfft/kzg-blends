#![no_main]
sp1_zkvm::entrypoint!(main);

use kzg_rs_blend::verify_blob_kzg_proof;
use sp1_zkvm::io::{commit, read};

pub fn main() {
    // Read inputs from the host
    println!("cycle-tracker-start: main");
    let blob = read::<Vec<u8>>();
    let commitment = read::<Vec<u8>>();
    let proof = read::<Vec<u8>>();

    println!("cycle-tracker-start: verify_blob_kzg_proof");
    let result = match verify_blob_kzg_proof(
        &blob,
        &commitment.try_into().unwrap(),
        &proof.try_into().unwrap(),
    ) {
        Ok(_) => true,
        Err(e) => {
            eprintln!("KZG proof verification failed: {:?}", e);
            false
        }
    };
    println!("cycle-tracker-end: verify_blob_kzg_proof");

    // Write the result back to the host
    commit(&result);
    println!("cycle-tracker-end: main");
}
