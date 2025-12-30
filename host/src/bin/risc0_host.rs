use kzg_rs_blend::KzgCommitmentBytes;
use risc0_zkvm::{default_prover, ExecutorEnv};

// Include auto-generated image_id.rs from risc0-guest
include!("../../../risc0-guest/elf/image_id.rs");

const ELF: &[u8] =
    include_bytes!("../../../risc0-guest/target/riscv32im-risc0-zkvm-elf/docker/risc0-guest.bin");

// Load blob and commitment from data directory
const BLOB: &[u8] = include_bytes!("../../../data/blob_13326465_0.bin");
const COMMITMENT: &[u8] = include_bytes!("../../../data/blob_13326465_0.cmt");

fn main() {
    // Load blob and commitment from embedded data
    let blob = BLOB;
    let commitment: KzgCommitmentBytes =
        COMMITMENT.try_into().expect("Commitment must be 48 bytes");

    // Compute KZG proof locally using kzg_rs_blend
    let kzg_proof =
        kzg_rs_blend::blob_to_proof(blob, &commitment).expect("Failed to compute proof");

    println!("Loaded blob: {} bytes", blob.len());
    println!("Loaded commitment: 0x{}", hex::encode(commitment));
    println!("Computed KZG proof: 0x{}", hex::encode(kzg_proof));

    // Build executor environment with inputs
    let env = ExecutorEnv::builder()
        .write(&blob.to_vec())
        .unwrap()
        .write(&commitment.to_vec())
        .unwrap()
        .write(&kzg_proof.to_vec())
        .unwrap()
        .build()
        .expect("Failed to build executor environment");

    println!("Setup RISC0 prover");
    // Get the default prover
    let prover = default_prover();

    println!("Execute guest program");
    // Execute the guest program and generate RISC0 proof
    let prove_info = prover
        .prove(env, ELF)
        .expect("Failed to execute guest program");

    // Verify the receipt using the image ID from auto-generated file
    prove_info
        .receipt
        .verify(risc0_zkvm::sha::Digest::from(IMAGE_ID_BYTES))
        .expect("RISC0 proof verification failed");

    // Read the result from the receipt journal
    let result: bool = prove_info
        .receipt
        .journal
        .decode()
        .expect("Failed to decode receipt journal");

    println!("✓ RISC0 proof verified successfully!");
    println!("Verification result: {}", result);
}
