use zeroize::Zeroizing;

/// `N` bytes from the operating system's CSPRNG. There is no fallback: a
/// key generated from anything weaker is not a key.
///
/// A failing OS random source is the one runtime failure here that stops
/// the process instead of returning an error: it is not reachable from any
/// input, nothing sound can continue without randomness, and `OsRng` (which
/// `crypto_box` uses for sealing) already panics the same way. Making every
/// key generation fallible for it would push the case onto every caller.
#[allow(clippy::expect_used)]
pub(crate) fn random_bytes<const N: usize>() -> Zeroizing<[u8; N]> {
    let mut bytes = Zeroizing::new([0u8; N]);
    getrandom::fill(bytes.as_mut_slice()).expect("the operating system's random source failed");
    bytes
}
