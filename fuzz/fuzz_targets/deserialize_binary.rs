#![no_main]

// Fuzz target for `Macaroon::deserialize_binary`, which skips the base64
// and JSON layers and goes straight to the V1 / V2 binary parsers. Useful
// because the base64 step of the top-level `deserialize` happens to filter
// out a lot of byte-level mutations before they reach the binary parser;
// fuzzing the binary path directly finds things the outer path hides.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = macaroon::Macaroon::deserialize_binary(data);
});
