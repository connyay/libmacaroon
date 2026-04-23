#![no_main]

// Fuzz target for the top-level `Macaroon::deserialize` entry point. It
// auto-detects V1, V2, and V2JSON tokens, so this harness covers all three
// parsers and the base64 layer. The only correctness guarantee is "never
// panic" — either a parse or an error is fine.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = libmacaroon::Macaroon::deserialize(data);
});
