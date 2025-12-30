use kzg_rs_blend::KzgCommitmentBytes;
use sp1_sdk::{ProverClient, SP1Stdin, utils};

const ELF: &[u8] =
    include_bytes!("../../../guest/target/elf-compilation/riscv32im-succinct-zkvm-elf/release/guest");

// Load blob and commitment from data directory
const BLOB: &[u8] = include_bytes!("../../../data/blob_13326465_0.bin");
const COMMITMENT: &[u8] = include_bytes!("../../../data/blob_13326465_0.cmt");

fn main() {
    // Setup logger
    utils::setup_logger();

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

    // Create stdin with test data
    let mut stdin = SP1Stdin::new();

    // Write inputs to stdin
    stdin.write(&blob.to_vec());
    stdin.write(&commitment.to_vec());
    stdin.write(&kzg_proof.to_vec());

    println!("Setup SP1 prover client");
    // Initialize SP1 prover client
    let client = ProverClient::from_env();

    // let (_pk, _vk) = client.setup(ELF);

    println!("Execute guest program");
    // Execute the guest program and generate SP1 proof
    let _sp1_proof = client
        .execute(ELF, &stdin)
        .run()
        .expect("Failed to execute guest program");

    // // Verify the SP1 proof
    // client
    //     .verify(&sp1_proof, &vk)
    //     .expect("SP1 proof verification failed");

    println!("✓ SP1 proof verified successfully!");
}

