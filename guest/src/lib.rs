use sp1_zkvm::prelude::*;
use kzg_rs_blend::verify_blob_kzg_proof;
use kzg_rs_blend::KzgCommitmentBytes;

#[sp1_zkvm::entrypoint]
pub fn main() {
    // Read inputs from the host
    let blob = SP1Stdin::read::<Vec<u8>>();
    let commitment = SP1Stdin::read::<KzgCommitmentBytes>();
    let proof = SP1Stdin::read::<KzgCommitmentBytes>();

    // Verify the blob KZG proof - 逻辑与host中的verify_test完全一致
    let result = match verify_blob_kzg_proof(&blob, &commitment, &proof) {
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
    SP1Stdout::write(&result);
}

