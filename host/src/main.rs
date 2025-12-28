use sp1_sdk::{utils, ProverClient, SP1Stdin};

const ELF: &[u8] = include_bytes!("../../guest/target/riscv32im-succinct-zkvm-elf/release/guest");

fn main() {
    // Setup logger
    utils::setup_logger();

    // Create stdin with test data
    let mut stdin = SP1Stdin::new();

    // Example blob (131072 bytes for EIP-4844)
    let blob = vec![0u8; 131072];
    let commitment: [u8; 48] = [0u8; 48]; // This should be the actual commitment
    let proof: [u8; 48] = [0u8; 48]; // This should be the actual proof

    // Write inputs to stdin
    stdin.write(&blob);
    stdin.write(&commitment.to_vec());
    stdin.write(&proof.to_vec());

    // Initialize SP1 prover client
    let client = ProverClient::from_env();

    let (pk, vk) = client.setup(ELF);
    // Execute the guest program and generate proof
    let proof = client
        .prove(&pk, &stdin)
        .groth16()
        .run()
        .expect("Failed to execute guest program");

    // Verify the proof
    client
        .verify(&proof, &vk)
        .expect("Proof verification failed");

    println!("✓ SP1 proof verified successfully!");
}
