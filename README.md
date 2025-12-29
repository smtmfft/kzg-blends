# Common ZK Project Structure

This project contains a zk project structure that mimics risc0/sp1's compilation pattern, used to compare the differences between `rust-kzg-zkcrypto` and other implementations, e.g. SP1's own `kzg-rs`.

## Project Structure

```
kzg-rs-blend/
├── Cargo.toml           # Workspace configuration
├── crates/              # Shared library code
│   └── kzg-rs-blend/   # KZG library
│       ├── Cargo.toml
│       └── src/
│           ├── lib.rs  # Contains verify_blob_kzg_proof function
│           └── error.rs # Error type definitions
├── host/                # SP1 host-side code
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs     # host main program
│       ├── lib.rs      # Shared verification functions and tests
│       └── bin/
│           └── verify_guest.rs  # Bin to test guest logic in host
└── guest/               # SP1 guest-side code
    ├── Cargo.toml
    └── src/
        └── lib.rs      # guest entry point, uses verify_blob_kzg_proof

```

## Usage

### 1. Build guest program

```bash
cd guest
cargo prove build
```

### 2. Build and run/profiling host program (mock execute ZK proof)

```bash
cd host
#cargo build --release
RUST_LOG=info SP1_PROVER=mock cargo run --bin host --release
```

### 3. (Optional) Test guest verification logic on host side

```bash
cd host
# Run the same verification logic as guest on host side
cargo run --bin verify_guest

# Or run tests
cargo test
```

This allows you to verify the KZG verification logic on the host side first before running in guest.

### 4. Workspace usage

The project is already configured as a workspace. The root `Cargo.toml` contains workspace configuration, and shared library code is located in the `crates/kzg-rs-blend/` directory.

## Guest Program Description

The `main` function in `guest/src/lib.rs` is the entry point of the guest program. It:
1. Reads blob, commitment, and proof from the host
2. Calls `kzg_rs_blend::verify_blob_kzg_proof` for verification
3. Writes the verification result back to the host

## Host Program Description

The program in `host/src/main.rs`:
1. Prepares test data (blob, commitment, proof)
2. Executes the guest program and generates ZK proof
3. Verifies the ZK proof

## Notes

- Ensure SP1 toolchain is installed
- Guest program needs to be compiled for `riscv32im-succinct-zkvm-elf` target platform
- Currently using example data; provide actual blob, commitment, and proof for real usage

## Rust Toolchain

This project uses Rust 1.88.0, specified in `rust-toolchain.toml`. rustup will automatically install and use this version when working in this directory.

