// 独立的bin用于在host端测试guest中的KZG验证逻辑，与guest中的逻辑完全一致
// 用法: cargo run --bin verify_guest
use kzg_rs_blend::verify_blob_kzg_proof;
use kzg_rs_blend::KzgCommitmentBytes;

fn main() {
    // 示例数据 - 与guest/src/lib.rs中的逻辑完全一致
    let blob = vec![0u8; 131072]; // EIP-4844 blob size
    let commitment: KzgCommitmentBytes = [0u8; 48]; // This should be the actual commitment
    let proof: KzgCommitmentBytes = [0u8; 48]; // This should be the actual proof

    // 验证逻辑 - 与guest/src/lib.rs中的逻辑完全一致
    let result = match verify_blob_kzg_proof(&blob, &commitment, &proof) {
        Ok(_) => {
            println!("✓ KZG proof verification successful!");
            true
        }
        Err(e) => {
            eprintln!("✗ KZG proof verification failed: {:?}", e);
            false
        }
    };

    if !result {
        std::process::exit(1);
    }
}

