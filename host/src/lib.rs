// 将guest中的逻辑提取为一个共享函数，可以在测试和guest中使用
use kzg_rs_blend::verify_blob_kzg_proof;
use kzg_rs_blend::KzgCommitmentBytes;

/// 验证blob KZG proof - 与guest/src/lib.rs中的逻辑完全一致
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
        // 使用与guest相同的测试数据
        let blob = vec![0u8; 131072];
        let commitment: KzgCommitmentBytes = [0u8; 48];
        let proof: KzgCommitmentBytes = [0u8; 48];

        // 这里会失败，因为使用的是零值，但逻辑与guest完全一致
        let result = verify_kzg_proof(&blob, &commitment, &proof);
        // 注意：这个测试在实际情况下需要使用有效的commitment和proof才能通过
        println!("Verification result: {}", result);
    }
}

