# S1: ring signature verification cost

Throwaway harness. The `lsag` crate here exists to be timed, not used: it has
no test vectors and has not been reviewed.

Needs a Rust toolchain with the `wasm32-unknown-unknown` target. The guest
must be built with the default `curve25519-dalek` backend for that target;
forcing the 64-bit backend makes it 2.5 times slower.

```sh
cargo build -p guest --target wasm32-unknown-unknown --release
cargo build -p host --release
target/release/host target/wasm32-unknown-unknown/release/guest.wasm opt3
```

The host checks that the guest accepts a valid signature and rejects a
tampered one before timing, then prints the median of 7 runs per case:
natively, in wasmtime with the engine settings of `freenet-core`, and in
wasmtime with its defaults.

Results are in the [top-level README](../../README.md#ring-verification-cost).
