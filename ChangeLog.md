# libmacaroon Change Log

## Version 0.2.0 - 2026-04-23 (libmacaroon)

Ergonomics improvements from first-wave dogfooding feedback. Both
changes are breaking at call sites, but both are mechanical rewrites.

- **`Macaroon::create`** now takes `Option<&str>` for the location
  instead of `Option<String>`. A call site that was
  `Some("http://bank".to_string())` or `Some("http://bank".into())`
  becomes `Some("http://bank")`. The macaroon still owns its location
  (the crate does one `.to_string()` internally), but the allocation
  disappears from every call site.
- **`add_first_party_caveat`** and **`add_third_party_caveat`** now
  return `Result<&mut Self>` instead of `Result<()>`, so calls chain:

  ```rust
  let mut m = Macaroon::create(Some("loc"), &key, "id")?;
  m.add_first_party_caveat("account = 12345")?
      .add_first_party_caveat("user = alice")?;
  ```

  Same `?` count, fewer lines, reads as a pipeline. The cap checks that
  made the calls fallible in 0.1.0 are unchanged — this is only a
  return-type tweak.

## Version 0.1.0 - 2026-04-23 (libmacaroon)

First release under the `libmacaroon` name. This is a fork of the
[`macaroon`](https://crates.io/crates/macaroon) crate
(`macaroon-rs/macaroon`, last released as 0.3.0 in Oct 2022), published
fresh on crates.io under the new name — so the version resets to 0.1.0
even though the internals continue from `macaroon 0.3.0` plus the
pre-release hardening below.

The API is source-compatible with `macaroon 0.3.0` in spirit, but many
signatures changed for the hardening work (see "API changes from
`macaroon 0.3.0`" below).

### API changes from `macaroon 0.3.0`

Several breaking changes from the original `macaroon 0.3.0` API.

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
- MSRV is now 1.71 (was claimed 1.56 but effective MSRV was higher
  because of transitive deps). 1.71 matches the real floor from
  `env_logger 0.11` and `quote 1.0.45`.
- `env_logger` and `time` dev-dependencies removed. `env_logger` was
  declared but never used; `time` backed a single test helper that
  now compares ISO-8601 timestamps lexicographically against a fixed
  reference (equivalent semantics with no dep).
- Cargo.lock is now committed so `cargo audit` runs reproducibly in CI
  and everyone gets the same dep set in local dev. Published crate is
  unaffected (Cargo excludes the lockfile from packaged libraries).
- CI modernized: `actions/checkout@v4`, `dtolnay/rust-toolchain@stable`,
  `Swatinem/rust-cache@v2`, separate jobs for `fmt`, `clippy -D warnings`,
  MSRV, WASM target, and `rustsec/audit-check`. All build steps now
  use `--locked`.

**Correctness polish:**
- V2JSON decoder rejects tokens whose top-level `v` field isn't `2`.
- V1/V2 binary format sniff in `Macaroon::deserialize_binary` now accepts
  only actual hex digits (`'0'..='9' | 'a'..='f' | 'A'..='F'`) as a V1
  first byte, rather than any uppercase letter.
- `Verifier::verify` rejects duplicate-identifier discharges explicitly
  instead of silently de-duplicating on HashMap insertion.

**API ergonomics (continued):**
- `Caveat::as_first_party` / `Caveat::as_third_party` accessors added so
  callers can skip the `match` when they already know or want to filter
  for a specific caveat kind.
- Example doctests in `lib.rs` and `README.md` rewritten in `?`-style
  instead of `match { Err(e) => panic!(..) }`.

**Testing:**
- Property-based tests under `tests/proptest_roundtrip.rs` cover
  round-trip of random macaroons through all three formats, correct-key
  verification, wrong-key rejection, and "never panic on arbitrary input"
  for the deserialization entry points.
- `cargo-fuzz` scaffolding under `fuzz/` with targets for
  `Macaroon::deserialize` and `Macaroon::deserialize_binary`. Out-of-band
  (nightly only); see `fuzz/README.md`.

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
