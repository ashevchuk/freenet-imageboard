//! Throwaway spike: times ring-signature verification natively and inside
//! wasmtime, under Freenet's engine settings and under wasmtime's defaults.
//!
//! Usage: host <guest.wasm> <label>

use std::time::{Duration, Instant};

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha512};
use wasmtime::{Config, Engine, Instance, Module, OptLevel, Store};

const RING_SIZES: [usize; 4] = [16, 32, 64, 128];
const SCOPE: &[u8] = b"thread-id-0123456789abcdef0123456789abcdef";
const MESSAGE: &[u8] = b"thread-id || session public key";

// Mirrors `create_engine` in freenet-core
// crates/core/src/wasm_runtime/engine/wasmtime_engine.rs at 83d3397, except
// the stack sizes, which need wasmtime's async support and do not affect
// execution speed.
const WASM_PAGE_SIZE: u64 = 65536;
const DEFAULT_MAX_MEMORY_PAGES: u64 = 4096;

fn freenet_config() -> Config {
    let mut config = Config::new();
    config.epoch_interruption(true);
    config.memory_reservation(DEFAULT_MAX_MEMORY_PAGES * WASM_PAGE_SIZE);
    config.memory_guard_size(WASM_PAGE_SIZE);
    config.memory_reservation_for_growth(0);
    config.cranelift_opt_level(OptLevel::None);
    config
}

fn secret(index: usize) -> Scalar {
    Scalar::from_hash(
        Sha512::new()
            .chain_update(b"s1-spike/fixture-key")
            .chain_update((index as u64).to_le_bytes()),
    )
}

struct Fixture {
    valid: Vec<u8>,
    tampered: Vec<u8>,
}

fn ring_fixture(n: usize) -> Fixture {
    let ring: Vec<[u8; 32]> = (0..n)
        .map(|i| (secret(i) * ED25519_BASEPOINT_POINT).compress().to_bytes())
        .collect();
    let signer = n / 2;
    let signature =
        lsag::sign(&secret(signer), &ring, signer, SCOPE, MESSAGE).expect("fixture ring is valid");
    assert!(lsag::verify(&ring, SCOPE, MESSAGE, &signature));
    assert!(!lsag::verify(&ring, b"another scope", MESSAGE, &signature));

    let valid = lsag::encode(&ring, SCOPE, MESSAGE, &signature);
    let mut tampered = valid.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    assert!(lsag::verify_encoded(&valid));
    assert!(!lsag::verify_encoded(&tampered));
    Fixture { valid, tampered }
}

fn ed25519_fixture() -> Fixture {
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let mut valid = key.verifying_key().to_bytes().to_vec();
    valid.extend_from_slice(&key.sign(MESSAGE).to_bytes());
    valid.extend_from_slice(MESSAGE);
    let mut tampered = valid.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    Fixture { valid, tampered }
}

fn median_per_call(mut run: impl FnMut(), iterations: u32) -> Duration {
    let mut samples: Vec<Duration> = (0..7)
        .map(|_| {
            let start = Instant::now();
            for _ in 0..iterations {
                run();
            }
            start.elapsed() / iterations
        })
        .collect();
    samples.sort();
    samples[samples.len() / 2]
}

fn millis(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}

struct Guest {
    store: Store<()>,
    instance: Instance,
}

impl Guest {
    fn new(config: &Config, wasm: &[u8]) -> wasmtime::Result<Self> {
        let engine = Engine::new(config)?;
        let module = Module::new(&engine, wasm)?;
        let mut store = Store::new(&engine, ());
        store.set_epoch_deadline(u64::MAX);
        let instance = Instance::new(&mut store, &module, &[])?;
        Ok(Self { store, instance })
    }

    fn load(&mut self, bytes: &[u8]) -> wasmtime::Result<(u32, u32)> {
        let alloc = self
            .instance
            .get_typed_func::<u32, u32>(&mut self.store, "alloc")?;
        let pointer = alloc.call(&mut self.store, bytes.len() as u32)?;
        let memory = self
            .instance
            .get_memory(&mut self.store, "memory")
            .expect("guest exports memory");
        memory.write(&mut self.store, pointer as usize, bytes)?;
        Ok((pointer, bytes.len() as u32))
    }

    fn time(&mut self, export: &str, fixture: &Fixture, iterations: u32) -> wasmtime::Result<Duration> {
        let function = self
            .instance
            .get_typed_func::<(u32, u32), i32>(&mut self.store, export)?;
        let valid = self.load(&fixture.valid)?;
        let tampered = self.load(&fixture.tampered)?;
        assert_eq!(function.call(&mut self.store, valid)?, 1, "{export}: valid input rejected");
        assert_eq!(function.call(&mut self.store, tampered)?, 0, "{export}: tampered input accepted");
        let store = &mut self.store;
        Ok(median_per_call(
            || {
                let result = function.call(&mut *store, valid).expect("guest call");
                assert_eq!(result, 1);
            },
            iterations,
        ))
    }
}

fn main() -> wasmtime::Result<()> {
    let mut arguments = std::env::args().skip(1);
    let wasm_path = arguments.next().expect("usage: host <guest.wasm> <label>");
    let label = arguments.next().expect("usage: host <guest.wasm> <label>");
    let wasm = std::fs::read(&wasm_path)?;

    let ed25519 = ed25519_fixture();
    let rings: Vec<(usize, Fixture)> = RING_SIZES.iter().map(|&n| (n, ring_fixture(n))).collect();

    println!("guest build: {label} ({} bytes)", wasm.len());
    println!("{:<34} {:>12} {:>12}", "engine", "case", "ms per call");

    for (n, fixture) in &rings {
        let elapsed = median_per_call(|| assert!(lsag::verify_encoded(&fixture.valid)), 20);
        println!("{:<34} {:>12} {:>12.3}", "native", format!("ring {n}"), millis(elapsed));
    }

    let engines = [
        ("wasmtime, freenet settings", freenet_config()),
        ("wasmtime, default settings", Config::new()),
    ];
    for (name, config) in &engines {
        let mut guest = Guest::new(config, &wasm)?;
        let elapsed = guest.time("ed25519_verify", &ed25519, 200)?;
        println!("{:<34} {:>12} {:>12.3}", name, "ed25519", millis(elapsed));
        for (n, fixture) in &rings {
            let elapsed = guest.time("ring_verify", fixture, 10)?;
            println!("{:<34} {:>12} {:>12.3}", name, format!("ring {n}"), millis(elapsed));
        }
    }
    Ok(())
}
