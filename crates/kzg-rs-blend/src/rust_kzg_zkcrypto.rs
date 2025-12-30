use crate::error::{RaikoError, RaikoResult};
use crate::traits::KzgImplementation;
use crate::KzgCommitmentBytes;
use kzg::kzg_proofs::KZGSettings;
use kzg_traits::G1;
use kzg_traits::eip_4844::{
    blob_to_kzg_commitment_rust, bytes_to_blob, compute_blob_kzg_proof_rust,
    verify_blob_kzg_proof_rust,
};
use std::sync::OnceLock;

/// Default embedded KZG settings in `bincode` format.
static DEFAULT_KZG_SETTINGS_BIN: &[u8] = include_bytes!("../kzg_settings.bin");

/// Static KZG settings loaded from the default trusted setup.
static KZG_SETTINGS: OnceLock<Result<KZGSettings, String>> = OnceLock::new();

/// Get or initialize the KZG settings.
fn get_kzg_settings() -> RaikoResult<&'static KZGSettings> {
    println!("cycle-tracker-start: get_kzg_settings");
    let res = match KZG_SETTINGS.get_or_init(init_kzg_settings) {
        Ok(settings) => Ok(settings),
        Err(e) => Err(RaikoError::InvalidBlobOption(format!(
            "KZG settings initialization failed: {e}"
        ))),
    };
    println!("cycle-tracker-end: get_kzg_settings");
    res
}

/// Initialize KZG settings from the embedded trusted setup bytes.
fn init_kzg_settings() -> Result<KZGSettings, String> {
    println!("cycle-tracker-start: init_kzg_settings");
    let res = bincode::deserialize(DEFAULT_KZG_SETTINGS_BIN)
        .map_err(|e| format!("bincode deserialize KZGSettings failed: {e}"));
    println!("cycle-tracker-end: init_kzg_settings");
    res
}

fn g1_to_kzg_commitment_bytes(g1_point: &impl G1) -> KzgCommitmentBytes {
    let bytes = g1_point.to_bytes();
    let mut result = [0u8; 48];
    result.copy_from_slice(&bytes);
    result
}

/// Implementation using rust-kzg-zkcrypto.
pub struct RustKzgZkcrypto;

impl KzgImplementation for RustKzgZkcrypto {
    fn blob_to_commitment(&self, blob: &[u8]) -> RaikoResult<KzgCommitmentBytes> {
        let kzg_settings = get_kzg_settings()?;
        let blob_fields = bytes_to_blob(blob)
            .map_err(|e| RaikoError::InvalidBlobOption(format!("Failed to convert blob: {}", e)))?;

        let commitment = blob_to_kzg_commitment_rust(&blob_fields, kzg_settings).map_err(|e| {
            RaikoError::InvalidBlobOption(format!("Failed to compute commitment: {}", e))
        })?;

        Ok(g1_to_kzg_commitment_bytes(&commitment))
    }

    fn blob_to_proof(
        &self,
        blob: &[u8],
        commitment: &KzgCommitmentBytes,
    ) -> RaikoResult<KzgCommitmentBytes> {
        let kzg_settings = get_kzg_settings()?;
        let blob_fields = bytes_to_blob(blob)
            .map_err(|e| RaikoError::InvalidBlobOption(format!("Failed to convert blob: {}", e)))?;

        let kzg_commitment = G1::from_bytes(commitment)
            .map_err(|e| RaikoError::InvalidBlobOption(format!("Invalid commitment: {}", e)))?;

        let proof = compute_blob_kzg_proof_rust(&blob_fields, &kzg_commitment, kzg_settings)
            .map_err(|e| RaikoError::InvalidBlobOption(format!("Failed to compute proof: {}", e)))?;

        Ok(g1_to_kzg_commitment_bytes(&proof))
    }

    fn verify_blob_kzg_proof(
        &self,
        blob: &[u8],
        commitment: &KzgCommitmentBytes,
        proof: &KzgCommitmentBytes,
    ) -> RaikoResult<()> {
        println!("cycle-tracker-start: verify_blob_kzg_proof_with_settings");
        let kzg_settings = get_kzg_settings()?;
        let blob_fields = bytes_to_blob(blob)
            .map_err(|e| RaikoError::InvalidBlobOption(format!("Failed to convert blob: {}", e)))?;

        let kzg_commitment = G1::from_bytes(commitment)
            .map_err(|e| RaikoError::InvalidBlobOption(format!("Invalid commitment: {}", e)))?;
        let kzg_proof = G1::from_bytes(proof)
            .map_err(|e| RaikoError::InvalidBlobOption(format!("Invalid proof: {}", e)))?;

        let is_valid = verify_blob_kzg_proof_rust(&blob_fields, &kzg_commitment, &kzg_proof, kzg_settings)
            .map_err(|e| RaikoError::InvalidBlobOption(format!("Verification error: {}", e)))?;
        if !is_valid {
            return Err(RaikoError::InvalidBlobOption(
                "KZG proof verification failed".to_string(),
            ));
        }
        println!("cycle-tracker-end: verify_blob_kzg_proof_with_settings");
        Ok(())
    }
}

