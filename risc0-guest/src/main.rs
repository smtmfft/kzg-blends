#![no_main]
risc0_zkvm::guest::entry!(main);

use kzg_rs_blend::verify_blob_kzg_proof;
use risc0_zkvm::guest::env;

pub fn main() {
    // Read inputs from the host
    println!("cycle-tracker-start: main");
    let blob: Vec<u8> = env::read();
    let commitment: Vec<u8> = env::read();
    let proof: Vec<u8> = env::read();

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
    env::commit(&result);
    println!("cycle-tracker-end: main");
}

