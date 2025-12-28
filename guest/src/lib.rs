#![no_main]
sp1_zkvm::entrypoint!(main);

use kzg_rs_blend::verify_blob_kzg_proof;
use sp1_zkvm::io::{commit, read};

pub fn main() {
    // Read inputs from the host
    let blob = read::<Vec<u8>>();
    let commitment = read::<Vec<u8>>();
    let proof = read::<Vec<u8>>();

    let result = match verify_blob_kzg_proof(
        &blob,
        &commitment.try_into().unwrap(),
        &proof.try_into().unwrap(),
    ) {
        Ok(_) => {
            // Verification successful
            true
        }
        Err(e) => {
            // Verification failed
            eprintln!("KZG proof verification failed: {:?}", e);
            false
        }
    };

    // Write the result back to the host
    commit(&result);
}
