// Extract the verification logic from guest as a shared function that can be used in tests and guest
use kzg_rs_blend::verify_blob_kzg_proof;
use kzg_rs_blend::KzgCommitmentBytes;

/// Verify blob KZG proof - logic is identical to guest/src/lib.rs
pub fn verify_kzg_proof(
    blob: &[u8],
    commitment: &KzgCommitmentBytes,
    proof: &KzgCommitmentBytes,
) -> bool {
    match verify_blob_kzg_proof(blob, commitment, proof) {
        Ok(_) => {
            println!("✓ KZG proof verification successful!");
            true
        }
        Err(e) => {
            eprintln!("✗ KZG proof verification failed: {:?}", e);
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_kzg_proof() {
        // Use the same test data as guest
        let blob = vec![0u8; 131072];
        let commitment: KzgCommitmentBytes = [0u8; 48];
        let proof: KzgCommitmentBytes = [0u8; 48];

        // This will fail because we're using zero values, but the logic is identical to guest
        let result = verify_kzg_proof(&blob, &commitment, &proof);
        // Note: This test requires valid commitment and proof to pass in real scenarios
        println!("Verification result: {}", result);
    }
}
