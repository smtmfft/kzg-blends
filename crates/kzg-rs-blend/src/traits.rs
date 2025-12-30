use crate::error::RaikoResult;
use crate::KzgCommitmentBytes;

/// Trait for KZG implementations providing blob commitment, proof, and verification.
pub trait KzgImplementation {
    /// Convert blob to KZG commitment.
    fn blob_to_commitment(&self, blob: &[u8]) -> RaikoResult<KzgCommitmentBytes>;

    /// Compute KZG proof for a blob and its commitment.
    fn blob_to_proof(
        &self,
        blob: &[u8],
        commitment: &KzgCommitmentBytes,
    ) -> RaikoResult<KzgCommitmentBytes>;

    /// Verify blob KZG proof.
    fn verify_blob_kzg_proof(
        &self,
        blob: &[u8],
        commitment: &KzgCommitmentBytes,
        proof: &KzgCommitmentBytes,
    ) -> RaikoResult<()>;
}

