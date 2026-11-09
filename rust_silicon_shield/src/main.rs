//! Standalone probe for the TAUHAULITY native core.
//!
//! The binary exists so the toolchain, the code generation and the exported
//! primitives can be validated without a Python interpreter in the loop. The
//! Python loader cross-checks the same vectors at import time; running this
//! probe first makes a failure attributable to the Rust side alone.
//!
//! Usage:
//!   tauhaulity_shield_probe [--self-test] [--bench] [--version] [--help]
//!
//! Exit codes: 0 success, 1 a vector mismatch, 2 usage error.

use std::time::Instant;

use tauhaulity_silicon_shield::{crc64, qpc, sha256, shannon};

/// Expected SHA-256 digests from FIPS 180-4, paired with their inputs.
const SHA_VECTORS: [(&[u8], &str); 3] = [
    (
        b"",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        b"abc",
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    ),
    (
        b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
    ),
];

/// Expected CRC-64 values produced by the Python reference implementation.
const CRC_VECTORS: [(&[u8], u64); 4] = [
    (b"", 0),
    (b"a", 0x6e77_a179_cb48_b4d6),
    (b"123456789", 0x4db9_a9f8_7ec1_0c59),
    (
        b"The quick brown fox jumps over the lazy dog",
        0x7801_c8eb_84ec_729c,
    ),
];

/// Expected Shannon entropy values produced by the Python reference.
const ENTROPY_VECTORS: [(&[u8], f64, f64); 3] = [
    (b"", 0.0, 0.0),
    (b"abcd", 2.0, 1e-12),
    (&[0u8; 64], 0.0, 0.0),
];

fn print_version() {
    println!("tauhaulity_silicon_shield {}", tauhaulity_silicon_shield::VERSION);
}

fn self_test() -> bool {
    let mut ok = true;
    for (payload, expected) in SHA_VECTORS {
        let measured = sha256::to_hex(&sha256::digest(payload));
        let passed = measured == expected;
        ok &= passed;
        println!(
            "sha256[{:?}] {}",
            if payload.len() > 12 { "<long>" } else { std::str::from_utf8(payload).unwrap_or("?") },
            if passed { "ok" } else { "FAIL" }
        );
        if !passed {
            println!("  expected {expected}\n  measured {measured}");
        }
    }
    for (payload, expected) in CRC_VECTORS {
        let measured = crc64::checksum(payload);
        let passed = measured == expected;
        ok &= passed;
        println!(
            "crc64[{:?}] {}",
            if payload.len() > 12 { "<long>" } else { std::str::from_utf8(payload).unwrap_or("?") },
            if passed { "ok" } else { "FAIL" }
        );
        if !passed {
            println!("  expected {expected:#018x}\n  measured {measured:#018x}");
        }
    }
    for (payload, expected, tolerance) in ENTROPY_VECTORS {
        let measured = shannon::entropy(payload);
        let passed = (measured - expected).abs() <= tolerance;
        ok &= passed;
        println!("shannon[{} bytes] {}", payload.len(), if passed { "ok" } else { "FAIL" });
        if !passed {
            println!("  expected {expected}\n  measured {measured}");
        }
    }
    let mut previous = qpc::counter();
    let mut monotonic = true;
    for _ in 0..100_000 {
        let current = qpc::counter();
        monotonic &= current >= previous;
        previous = current;
    }
    ok &= monotonic;
    println!("qpc[100000 samples] {}", if monotonic { "ok" } else { "FAIL" });
    ok
}

fn bench() -> bool {
    let payload = vec![0x5Au8; 1024 * 1024];
    let started = Instant::now();
    let digest = sha256::digest(&payload);
    let sha_elapsed = started.elapsed();

    let started = Instant::now();
    let mut checksum = 0u64;
    for _ in 0..16 {
        checksum = crc64::checksum(&payload);
    }
    let crc_elapsed = started.elapsed();

    let started = Instant::now();
    let mut density = 0.0f64;
    for _ in 0..16 {
        density = shannon::entropy(&payload);
    }
    let entropy_elapsed = started.elapsed();

    let started = Instant::now();
    let mut counter = qpc::counter();
    for _ in 0..1_000_000 {
        counter = counter.wrapping_add(qpc::counter());
    }
    let qpc_elapsed = started.elapsed();

    let sha_mib = 1.0 / sha_elapsed.as_secs_f64();
    let crc_mib = 16.0 / crc_elapsed.as_secs_f64();
    let entropy_mib = 16.0 / entropy_elapsed.as_secs_f64();
    let qpc_rate = 1_000_000.0 / qpc_elapsed.as_secs_f64();

    println!("sha256   {sha_mib:8.1} MiB/s  {}", sha256::to_hex(&digest));
    println!("crc64    {crc_mib:8.1} MiB/s  {checksum:#018x}");
    println!("shannon  {entropy_mib:8.1} MiB/s  {density:.6}");
    println!("qpc      {qpc_rate:8.1} calls/s  {counter}");
    true
}

fn usage(program: &str) -> i32 {
    eprintln!("usage: {program} [--self-test] [--bench] [--version] [--help]");
    eprintln!("  --self-test  verify the built-in digest, checksum and entropy vectors (default)");
    eprintln!("  --bench      measure throughput of the native primitives");
    2
}

fn main() {
    let mut args = std::env::args();
    let program = args.next().unwrap_or_else(|| "tauhaulity_shield_probe".to_string());
    let mut run_self_test = false;
    let mut run_bench = false;
    for argument in args {
        match argument.as_str() {
            "--self-test" => run_self_test = true,
            "--bench" => run_bench = true,
            "--version" | "-V" => {
                print_version();
                return;
            }
            "--help" | "-h" => {
                usage(&program);
                return;
            }
            other => {
                eprintln!("unknown argument: {other}");
                std::process::exit(usage(&program));
            }
        }
    }
    if !run_self_test && !run_bench {
        run_self_test = true;
    }
    if run_self_test && !self_test() {
        eprintln!("self-test failed");
        std::process::exit(1);
    }
    if run_bench && !bench() {
        eprintln!("benchmark failed");
        std::process::exit(1);
    }
}
