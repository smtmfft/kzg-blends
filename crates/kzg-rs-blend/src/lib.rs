mod error;
mod kzg_rs;
mod rust_kzg_zkcrypto;
mod traits;

pub use error::{RaikoError, RaikoResult};
pub use traits::KzgImplementation;

use alloy_primitives::B256;
use kzg_traits::eip_4844::hash;

pub const VERSIONED_HASH_VERSION_KZG: u8 = 0x01;

pub type KzgField = [u8; 32];
pub type KzgCommitmentBytes = [u8; 48];

/// Default KZG implementation (rust-kzg-zkcrypto)
#[cfg(feature = "rust-kzg-zkcrypto")]
pub static DEFAULT_IMPL: rust_kzg_zkcrypto::RustKzgZkcrypto = rust_kzg_zkcrypto::RustKzgZkcrypto;
#[cfg(feature = "kzg-rs")]
pub static DEFAULT_IMPL: kzg_rs::KzgRs = kzg_rs::KzgRs;

/// Convert blob to KZG commitment using the default implementation.
pub fn blob_to_commitment(blob: &[u8]) -> RaikoResult<KzgCommitmentBytes> {
    DEFAULT_IMPL.blob_to_commitment(blob)
}

/// Compute a KZG proof for a blob and its corresponding commitment using the default implementation.
///
/// # Parameters
///
/// - `blob`: The raw blob data as a byte slice. In the context of [EIP-4844],
///   this should be the encoded blob whose polynomial commitment is being proven.
/// - `commitment`: The KZG commitment to the exact same blob, encoded as
///   48-byte `KzgCommitmentBytes`. This should typically be produced by
///   [`blob_to_commitment`] using the same `blob` input.
///
/// The `commitment` **must** correspond to the provided `blob`. Passing a
/// commitment that was computed from different data will result in a proof
/// that fails verification.
///
/// # Returns
///
/// Returns the KZG proof bytes (`KzgCommitmentBytes`) for the given `blob` and
/// `commitment`. This proof can be used with EIP-4844-compatible verification
/// routines to prove that the blob data matches its published KZG commitment.
///
/// For more details on how blob commitments and proofs are used in the
/// protocol, see [EIP-4844].
///
/// [EIP-4844]: https://eips.ethereum.org/EIPS/eip-4844
pub fn blob_to_proof(
    blob: &[u8],
    commitment: &KzgCommitmentBytes,
) -> RaikoResult<KzgCommitmentBytes> {
    DEFAULT_IMPL.blob_to_proof(blob, commitment)
}

/// Verify blob KZG proof using the default implementation.
pub fn verify_blob_kzg_proof(
    blob: &[u8],
    commitment: &KzgCommitmentBytes,
    proof: &KzgCommitmentBytes,
) -> RaikoResult<()> {
    DEFAULT_IMPL.verify_blob_kzg_proof(blob, commitment, proof)
}

/// Convert KZG commitment to versioned hash (EIP-4844).
///
/// Computes SHA256 hash of the commitment and sets the first byte to VERSIONED_HASH_VERSION_KZG.
pub fn commitment_to_version_hash(commitment: &KzgCommitmentBytes) -> B256 {
    let mut out = hash(commitment);
    out[0] = VERSIONED_HASH_VERSION_KZG;
    B256::from_slice(&out)
}

// Re-export implementations for direct use
pub use kzg_rs::KzgRs;
pub use rust_kzg_zkcrypto::RustKzgZkcrypto;

#[cfg(test)]
mod test {
    use super::*;
    use alloy_primitives::hex;
    use kzg_traits::eip_4844::BYTES_PER_BLOB;

    #[test]
    fn blob_commitment_version_hash_and_proof_verify() {
        let blob_bytes = vec![0u8; BYTES_PER_BLOB];
        let commitment_bytes = blob_to_commitment(&blob_bytes).expect("commitment");

        let proof = blob_to_proof(&blob_bytes, &commitment_bytes).expect("proof");

        verify_blob_kzg_proof(&blob_bytes, &commitment_bytes, &proof).expect("verify proof");

        let version_hash = commitment_to_version_hash(&commitment_bytes);
        let mut expected = hash(&commitment_bytes);
        expected[0] = VERSIONED_HASH_VERSION_KZG;
        assert_eq!(version_hash, B256::from_slice(&expected));
    }

    #[test]
    fn blob_to_proof_computes_verifiable_proof_for_mainnet_blob() {
        use std::fs;

        // Read blob from file
        let blob_file = concat!(env!("CARGO_MANIFEST_DIR"), "/../../data/blob_13326465_0.bin");
        let blob_bytes = fs::read(blob_file).expect("Failed to read blob file");
        println!("Read blob: {} bytes", blob_bytes.len());

        // Given commitment from mainnet
        let expected_commitment = "0xb8df58142f4397d25bf26f670fef31622428dbe4f22ad6e8c5386458ef28c698841904258320d98befd52b26edf1a26d";
        let commitment_str = expected_commitment
            .strip_prefix("0x")
            .unwrap_or(expected_commitment);
        let commitment_bytes: [u8; 48] = hex::decode(commitment_str)
            .expect("Failed to decode commitment hex")
            .try_into()
            .expect("Commitment must be 48 bytes");

        // Check that our computed commitment matches the expected commitment_hex above
        let computed_commitment =
            blob_to_commitment(&blob_bytes).expect("Failed to compute commitment");
        assert_eq!(
            computed_commitment, commitment_bytes,
            "Calculated commitment does not match expected commitment!"
        );

        // Compute proof
        let proof = blob_to_proof(&blob_bytes, &commitment_bytes).expect("Failed to compute proof");
        println!("Computed proof: 0x{}", hex::encode(proof));

        // Verify proof
        verify_blob_kzg_proof(&blob_bytes, &commitment_bytes, &proof)
            .expect("Failed to verify proof");

        println!("✓ Proof verified successfully!");
    }

    #[test]
    fn compare_implementations() {
        let blob_bytes = vec![0u8; BYTES_PER_BLOB];

        // Test rust-kzg-zkcrypto
        let rust_kzg = RustKzgZkcrypto;
        let commitment1 = rust_kzg.blob_to_commitment(&blob_bytes).expect("commitment");
        let proof1 = rust_kzg.blob_to_proof(&blob_bytes, &commitment1).expect("proof");
        rust_kzg
            .verify_blob_kzg_proof(&blob_bytes, &commitment1, &proof1)
            .expect("verify");

        // Test kzg-rs
        let kzg_rs = KzgRs;
        let commitment2 = kzg_rs.blob_to_commitment(&blob_bytes).expect("commitment");
        let proof2 = kzg_rs.blob_to_proof(&blob_bytes, &commitment2).expect("proof");
        kzg_rs.verify_blob_kzg_proof(&blob_bytes, &commitment2, &proof2)
            .expect("verify");

        // Compare commitments (they should match for the same blob)
        assert_eq!(
            commitment1, commitment2,
            "Commitments should match between implementations"
        );
        assert_eq!(
            proof1, proof2,
            "Proofs should match between implementations"
        );

        println!("✓ Both implementations produce identical results!");
    }
}
