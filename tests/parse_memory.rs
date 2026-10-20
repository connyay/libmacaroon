//! Parse-time memory on hostile tokens.
//!
//! The caps (`MAX_CAVEATS`, `MAX_FIELD_SIZE_BYTES`) only bound memory if the
//! parsers apply them as they go: one that materializes a whole token and
//! checks afterwards can be made to allocate many times the token's size.
//! This builds multi-megabyte tokens out of the cheapest possible caveats
//! and counts the heap bytes each parser allocates.
//!
//! The counting allocator is process-wide, so this file holds a single test.

use libmacaroon::{Macaroon, MacaroonError};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};

struct Counting;

static CURRENT: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

fn grew(by: usize) {
    let now = CURRENT.fetch_add(by, Relaxed) + by;
    PEAK.fetch_max(now, Relaxed);
}

// SAFETY: every call is forwarded to `System` unchanged; this only adds
// bookkeeping.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            grew(layout.size());
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        CURRENT.fetch_sub(layout.size(), Relaxed);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new = unsafe { System.realloc(ptr, layout, new_size) };
        if !new.is_null() {
            if new_size > layout.size() {
                grew(new_size - layout.size());
            } else {
                CURRENT.fetch_sub(layout.size() - new_size, Relaxed);
            }
        }
        new
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// Runs `f`, returning its result and the most heap it held at once.
fn peak_heap<T>(f: impl FnOnce() -> T) -> (T, usize) {
    let base = CURRENT.load(Relaxed);
    PEAK.store(base, Relaxed);
    let out = f();
    (out, PEAK.load(Relaxed) - base)
}

const CAVEATS: usize = 1_000_000;

/// Parsing up to `MAX_CAVEATS` caveats takes a few hundred KB; parsers that
/// ignored the cap until the end took 8-50x the token size.
const LIMIT: usize = 1 << 20;

#[test]
fn hostile_tokens_parse_in_bounded_memory() {
    // V2JSON: `{}` is the cheapest caveat, 3 bytes with its comma.
    let json = format!(
        r#"{{"v":2,"i":"k","c":[{}],"s64":"S-lnzR6gxrJrr2pKlO6bBbFYhtoLqF6MQqk8jQ4SXvw"}}"#,
        vec!["{}"; CAVEATS].join(",")
    );
    let (result, peak) = peak_heap(|| Macaroon::deserialize(&json));
    assert!(result.is_err());
    assert!(
        peak < LIMIT,
        "V2JSON: {} byte token peaked at {} bytes",
        json.len(),
        peak
    );

    // V2: version, identifier "k", EOS, then caveats with an empty
    // identifier (tag, zero length, EOS).
    let mut v2 = vec![2, 2, 1, b'k', 0];
    v2.extend([2, 0, 0].repeat(CAVEATS));
    let (result, peak) = peak_heap(|| Macaroon::deserialize_binary(&v2));
    assert!(matches!(result, Err(MacaroonError::TooManyCaveats)));
    assert!(
        peak < LIMIT,
        "V2: {} byte token peaked at {} bytes",
        v2.len(),
        peak
    );
}
