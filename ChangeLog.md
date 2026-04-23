# macaroon Change Log

## Version 0.3.1 - UNRELEASED (macaroon)

Pre-release hardening pass. Several breaking API changes — see README's
"API Changes (0.3.x)" section for the full list.

**Security / interop fixes:**
- V2JSON decoder now accepts URL-safe base64 in `i64`, `v64`, `l64`, and
  `s64` fields, and emits URL-safe base64 without padding. Previously only
  standard-alphabet padded input was accepted, breaking interop with
  libmacaroons and pymacaroons which emit URL-safe unpadded by spec.
- `Macaroon::create`, `add_first_party_caveat`, `add_third_party_caveat` now
  enforce `MAX_FIELD_SIZE_BYTES` (65535) on every field at construction, so
  producer and consumer agree: a macaroon this crate serializes is always
  one this crate can parse back. V1's 4-hex-digit packet header could
  previously silently truncate oversized fields at serialize time.
- Migrated from unmaintained `xsalsa20poly1305 0.9` to `crypto_secretbox
  0.1` (RUSTSEC-2023-0037). Same algorithm and wire format.
- Dropped `rand 0.8` dependency (RUSTSEC-2026-0097) in favor of a direct
  `getrandom` call on native and WASM alike.
- `getrandom` failures now propagate as `MacaroonError::RngError` instead
  of panicking — important on WASM where a sandboxed iframe without
  `crypto.getRandomValues` would otherwise abort the module.
- V2JSON decoder now rejects per-caveat tokens that set both plain and
  `*64` variants of the same field (`i`/`i64`, `l`/`l64`, `v`/`v64`),
  mirroring the top-level exclusion check.

**API ergonomics:**
- `Verifier` is now `Send + Sync` — `satisfy_general` closures now require
  `Fn(&[u8]) -> bool + Send + Sync + 'static`.
- `MacaroonKey::generate_random()` returns `Result<MacaroonKey>`.
- `MacaroonKey` no longer implements `Deref<Target = [u8]>` — use
  `.as_ref()` to go through the explicit byte accessor.
- Added public constants `MAX_CAVEATS` and `MAX_FIELD_SIZE_BYTES`.
- Added `MacaroonError::FieldTooLarge { field, size }` and
  `MacaroonError::RngError`.

**Packaging / CI:**
- MSRV bumped from 1.56 to 1.60 to match `zeroize 1.8` and
  `crypto_secretbox 0.1`.
- CI modernized: `actions/checkout@v4`, `dtolnay/rust-toolchain@stable`,
  `Swatinem/rust-cache@v2`, separate jobs for `fmt`, `clippy -D warnings`,
  MSRV, WASM target, and `rustsec/audit-check`.

Note: would increment to v0.4.0 if there are major changes.

## Version 0.3.0 - Oct 13, 2022 (macaroon)

This is a backwards-incompatible release with respect to serialized macaroon signatures, because the HMAC has changed. This version should have signatures interoperable with `libmacaroon-rs v0.1.x`, and with most popular Macaroon implementations in other languages.

- Revert HMAC back to SHA-256 (breaks signatures)
- Dependency updates
- Update Rust edition to 2021, and minimum required Rust version to v1.56
- Public API "flattened" (internal modules no longer exposed), and some internal cryptographic functions removed from API
- Fix several trivial panics deserializing tokens
- Flexible decoding of base64-encoded macaroons (either URL-safe base64 or "standard" base64)
- Refactor MacaroonError, MacaroonKey, and Macaroon::deserialize()

## Version 0.2.0 - Sep 24, 2021 (macaroon)

First release of [`macaroon`](https://crates.io/crates/macaroon) crate from the new [`macaroon-rs`](https://github.com/macaroon-rs) github organization.

Macaroon signatures created with this version are not compatible with prior releases, because of the HMAC change.

- Several refactors to code and API
- Dependencies updated
- Macaroon HMAC changed from SHA-256 to SHA-512-256

## Version 0.1.1 - Feb 22, 2017 (libmacaroon-rs)

- Coverage using [coveralls.io](https://coveralls.io/github/jacklund/libmacaroon-rs?branch=trunk)
- Expanded coverage of unit tests
- Bug fix for version 1 deserialization

## Version 0.1.0 - Feb 20, 2017 (libmacaroon-rs)

Initial commit. Functionality:

- Macaroons with first- and third-party caveats
- Serialization/Deserialization using [libmacaroons](https://github.com/rescrv/libmacaroons) version 1, 2, and 2J (JSON) formats
- Verification of first-party caveats using either exact string comparison or submitted verification function
- Verification of third-party caveats using discharge macaroons
