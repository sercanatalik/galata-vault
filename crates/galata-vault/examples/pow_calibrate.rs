//! Measure this machine's proof-of-work rate and suggest a difficulty.
//!
//!   cargo run --release -p galata-vault-proto --example pow_calibrate [target_seconds]
//!
//! Expected work at difficulty d is 2^d hashes, so the suggestion is the d
//! whose expected solve time is closest to the target (default 3 s).

use std::time::{Duration, Instant};

fn main() {
    let target: f64 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(3.0);
    let token = galata_vault::proto::pow::Challenge {
        id: [0x5a; 16],
        expires_at: i64::MAX,
        difficulty: 0,
    }
    .issue(&[1; 32]);

    let start = Instant::now();
    let mut hashes: u64 = 0;
    while start.elapsed() < Duration::from_secs(2) {
        for _ in 0..10_000 {
            std::hint::black_box(galata_vault::proto::pow::verify(&token, 64, hashes));
            hashes += 1;
        }
    }
    let rate = hashes as f64 / start.elapsed().as_secs_f64();
    let suggested = (rate * target).log2().round().clamp(8.0, 40.0) as u8;
    println!("rate: {:.2} M hashes/s (single thread)", rate / 1e6);
    for d in suggested.saturating_sub(2)..=suggested + 2 {
        let secs = 2f64.powi(i32::from(d)) / rate;
        let mark = if d == suggested { "  <- suggested" } else { "" };
        println!("difficulty {d:2}: expected {secs:7.2} s{mark}");
    }
}
