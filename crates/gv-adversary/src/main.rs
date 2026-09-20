//! `gv-adversary`: the malicious server as a process, for tests outside
//! Rust (the Python suite). Prints its URL on the first line of stdout, then
//! serves until killed. Scripted through the JSON control API under
//! `/__adversary/` (see the library).

use std::io::Write;

fn main() {
    let adv = gv_adversary::Adversary::start_controlled();
    let mut out = std::io::stdout().lock();
    writeln!(out, "{}", adv.url()).expect("stdout is writable");
    out.flush().expect("stdout is writable");
    drop(out);
    loop {
        std::thread::park();
    }
}
