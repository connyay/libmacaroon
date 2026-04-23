# Fuzz targets for `macaroon`

Runs under [`cargo-fuzz`] against the two deserialization entry points.

[`cargo-fuzz`]: https://github.com/rust-fuzz/cargo-fuzz

## Setup

```sh
rustup install nightly
cargo install cargo-fuzz
```

## Running

From the crate root (the parent of this directory):

```sh
cargo +nightly fuzz run deserialize
cargo +nightly fuzz run deserialize_binary
```

Each target runs until it either finds a panic/crash or you stop it with
`Ctrl-C`. Findings land under `fuzz/artifacts/<target>/` with a reproducer
file; the minimized corpus is kept under `fuzz/corpus/<target>/`.

## What they cover

- `deserialize` — top-level entry point that sniffs the format (V1, V2, or
  V2JSON) from the first byte, then delegates. Exercises the base64 layer,
  the JSON parser, and both binary parsers.
- `deserialize_binary` — skips base64 and JSON. Useful because the outer
  base64 step filters out many byte-level mutations before they reach the
  binary parser; fuzzing this directly finds bugs the outer path hides.

## Why it isn't in CI

`cargo-fuzz` requires a nightly toolchain and libFuzzer runtime, which add
meaningful overhead for little marginal value on pull requests (crashes
are rare once the obvious ones have been cleaned up). Run it out-of-band
before releases or after touching the parsers, and check any findings
into `tests/` as regression tests with a note about the input.
