//! Cryptographic operations layer
//!
//! Uses pure-Rust implementations from the RustCrypto ecosystem,
//! compatible with native and WebAssembly targets.

pub(crate) mod rustcrypto;

use crate::Result;
use rustcrypto::RustCryptoBackend;
use std::borrow::Borrow;
use std::ops::{Deref, DerefMut};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// Secret cryptographic key used to sign and verify Macaroons.
///
/// This is a wrapper type around an array of bytes of the correct size for the underlying
/// cryptographic primitives (currently 32 bytes). Keys can be either provided verbatim as raw
/// bytes; generated randomly; or generated via an HMAC from a byte string of any length. For
/// security, keys should be generated using at least 32 bytes of entropy, and stored securely.
///
/// Key material is zeroized on drop and compared in constant time to prevent
/// timing side-channel attacks. The `Debug` implementation is redacted.
///
/// ## Creation
///
/// ```rust
/// # use std::error::Error;
/// #
/// # fn main() -> Result<(), Box<dyn Error>> {
/// use macaroon::MacaroonKey;
/// extern crate base64;
///
/// // generate a new random key from scratch
/// let fresh_key = MacaroonKey::generate_random();
///
/// // generate from a byte string
/// let weak_example_key = MacaroonKey::generate(b"some-secret-here");
///
/// // import a base64-encoded key (eg, from a secrets vault)
/// let mut key_bytes: [u8; 32] = [0; 32];
/// key_bytes.copy_from_slice(&base64::decode("zV/IaqNgsWe2c22J5ilLY/d9DbxEir2z1bYBrzBemsM=")?);
/// let secret_key: MacaroonKey = key_bytes.into();
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Copy, Zeroize)]
pub struct MacaroonKey([u8; 32]);

impl std::fmt::Debug for MacaroonKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MacaroonKey([REDACTED])")
    }
}

impl PartialEq for MacaroonKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl Eq for MacaroonKey {}

impl AsRef<[u8; 32]> for MacaroonKey {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

impl AsRef<[u8]> for MacaroonKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Borrow<[u8; 32]> for MacaroonKey {
    fn borrow(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Deref for MacaroonKey {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for MacaroonKey {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<[u8; 32]> for MacaroonKey {
    /// Uses bytes directly as a MacaroonKey (with no HMAC)
    fn from(b: [u8; 32]) -> Self {
        MacaroonKey(b)
    }
}

impl From<&[u8; 32]> for MacaroonKey {
    /// Uses bytes directly as a MacaroonKey (with no HMAC)
    fn from(b: &[u8; 32]) -> Self {
        MacaroonKey(*b)
    }
}

impl MacaroonKey {
    /// Generate a new random key, using a secure random number generator.
    ///
    /// ```rust
    /// # use macaroon::MacaroonKey;
    /// let key = MacaroonKey::generate_random();
    /// ```
    pub fn generate_random() -> Self {
        RustCryptoBackend::generate_random_key()
    }

    /// Use some seed data to reproducibly generate a MacaroonKey via HMAC.
    ///
    /// ```rust
    /// # use macaroon::MacaroonKey;
    /// let key = MacaroonKey::generate(b"secret-byte-string");
    /// let key = MacaroonKey::generate("secret-unicode-string‽".as_bytes());
    ///
    /// let b = [5,4,3,2,1];
    /// let key = MacaroonKey::generate(&b);
    /// ```
    pub fn generate(seed: &[u8]) -> Self {
        generate_derived_key(seed)
    }

    /// Convert to Vec<u8>
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    /// Check if key is empty (all zeros)
    pub fn is_empty(&self) -> bool {
        self.0.iter().all(|&b| b == 0)
    }
}

const KEY_GENERATOR: MacaroonKey = MacaroonKey(*b"macaroons-key-generator\0\0\0\0\0\0\0\0\0");

fn generate_derived_key(key: &[u8]) -> MacaroonKey {
    hmac(&KEY_GENERATOR, key)
}

/// Generate HMAC using SHA-256
pub fn hmac<T, U>(key: &T, text: &U) -> MacaroonKey
where
    T: AsRef<[u8; 32]> + ?Sized,
    U: AsRef<[u8]> + ?Sized,
{
    RustCryptoBackend::hmac(key, text)
}

/// Generate HMAC using SHA-256 with two inputs
pub fn hmac2<T, U>(key: &T, text1: &U, text2: &U) -> MacaroonKey
where
    T: AsRef<[u8; 32]> + ?Sized,
    U: AsRef<[u8]> + ?Sized,
{
    RustCryptoBackend::hmac2(key, text1, text2)
}

/// Encrypt key material using authenticated encryption (XSalsa20-Poly1305)
pub fn encrypt_key<T>(key: &T, plaintext: &T) -> Vec<u8>
where
    T: AsRef<[u8; 32]> + ?Sized,
{
    RustCryptoBackend::encrypt_key(key, plaintext)
}

/// Decrypt key material using authenticated encryption (XSalsa20-Poly1305)
pub fn decrypt_key<T, U>(key: &T, data: &U) -> Result<MacaroonKey>
where
    T: AsRef<[u8; 32]> + ?Sized,
    U: AsRef<[u8]> + ?Sized,
{
    RustCryptoBackend::decrypt_key(key, data)
}
