use crate::KzgCommitmentBytes;
use crate::error::{RaikoError, RaikoResult};
use crate::traits::KzgImplementation;
use kzg_rs::{Blob, Bytes48, KzgProof, KzgSettings};
use std::sync::OnceLock;

/// Default embedded KZG settings for kzg-rs.
static KZG_RS_SETTINGS: OnceLock<Result<KzgSettings, String>> = OnceLock::new();

/// Get or initialize the KZG settings for kzg-rs.
fn get_kzg_rs_settings() -> RaikoResult<&'static KzgSettings> {
    println!("cycle-tracker-start: get_kzg_rs_settings");
    let res = KZG_RS_SETTINGS
        .get_or_init(|| {
            KzgSettings::load_trusted_setup_file()
                .map_err(|e| format!("Failed to load kzg-rs trusted setup: {:?}", e))
        })
        .as_ref()
        .map_err(|e| {
            RaikoError::InvalidBlobOption(format!("KZG settings initialization failed: {e}"))
        });
    println!("cycle-tracker-end: get_kzg_rs_settings");
    res
}

/// Implementation using succinctlabs/kzg-rs.
///
/// Note: kzg-rs currently only provides verification functionality.
/// For commitment and proof computation, we fall back to rust-kzg-zkcrypto.
pub struct KzgRs;

impl KzgImplementation for KzgRs {
    fn blob_to_commitment(&self, blob: &[u8]) -> RaikoResult<KzgCommitmentBytes> {
        // kzg-rs doesn't provide blob_to_commitment, use rust-kzg-zkcrypto for now
        // TODO: Implement using kzg-rs if available
        use crate::rust_kzg_zkcrypto::RustKzgZkcrypto;
        RustKzgZkcrypto.blob_to_commitment(blob)
    }

    fn blob_to_proof(
        &self,
        blob: &[u8],
        commitment: &KzgCommitmentBytes,
    ) -> RaikoResult<KzgCommitmentBytes> {
        // kzg-rs doesn't provide compute_blob_kzg_proof, use rust-kzg-zkcrypto for now
        // TODO: Implement using kzg-rs if available
        use crate::rust_kzg_zkcrypto::RustKzgZkcrypto;
        RustKzgZkcrypto.blob_to_proof(blob, commitment)
    }

    fn verify_blob_kzg_proof(
        &self,
        blob: &[u8],
        commitment: &KzgCommitmentBytes,
        proof: &KzgCommitmentBytes,
    ) -> RaikoResult<()> {
        let kzg_settings = get_kzg_rs_settings()?;
        let blob_obj = Blob::from_slice(blob)
            .map_err(|e| RaikoError::InvalidBlobOption(format!("Invalid blob: {:?}", e)))?;

        let commitment_bytes = Bytes48::from_slice(commitment)
            .map_err(|e| RaikoError::InvalidBlobOption(format!("Invalid commitment: {:?}", e)))?;
        let proof_bytes = Bytes48::from_slice(proof)
            .map_err(|e| RaikoError::InvalidBlobOption(format!("Invalid proof: {:?}", e)))?;

        println!("cycle-tracker-start: verify_blob_kzg_proof");
        let is_valid = KzgProof::verify_blob_kzg_proof(
            blob_obj,
            &commitment_bytes,
            &proof_bytes,
            kzg_settings,
        )
        .map_err(|e| RaikoError::InvalidBlobOption(format!("Verification error: {:?}", e)))?;
        println!("cycle-tracker-end: verify_blob_kzg_proof");

        if !is_valid {
            return Err(RaikoError::InvalidBlobOption(
                "KZG proof verification failed".to_string(),
            ));
        }

        Ok(())
    }
}
