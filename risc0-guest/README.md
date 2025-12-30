# RISC0 Guest Build

## Building the Guest ELF

```bash
cargo risczero build
```

## Auto-generating ImageID

After building, you can automatically extract the ImageID and generate `image_id.rs`:

```bash
# Method 1: Pipe the build output
cargo risczero build 2>&1 | ./gen_image_id_from_build.sh

# Method 2: Run build first, then extract (if you saved the output)
./gen_image_id_from_build.sh < build_output.txt
```

The script will generate `image_id.rs` with the ImageID extracted from the build output.

## Manual Update

If the auto-generation doesn't work, you can manually update `image_id.rs` with the ImageID from the build output:

```
ImageID: acbb9d06483b0c2a711b66d1009f630394c073d7b69ce0813e1c3a5488933d6f
```

Copy the hex string and update `IMAGE_ID_HEX` and `IMAGE_ID_BYTES` in `image_id.rs`.


