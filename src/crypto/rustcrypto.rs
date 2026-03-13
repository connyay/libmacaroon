//! RustCrypto cryptographic backend implementation
//!
//! Uses pure Rust implementations from the RustCrypto project,
//! compatible with WebAssembly and other constrained environments.

use super::MacaroonKey;
use crate::error::MacaroonError;
use crate::Result;
use hmac::{Hmac, Mac};
use log::error;
use sha2::Sha256;
use xsalsa20poly1305::{
    aead::{Aead, KeyInit},
    Key as AeadKey, Nonce, XSalsa20Poly1305,
};

#[cfg(not(target_arch = "wasm32"))]
use rand::RngCore;

type HmacSha256 = Hmac<Sha256>;

pub(crate) struct RustCryptoBackend;

impl RustCryptoBackend {
    pub fn hmac<T, U>(key: &T, text: &U) -> MacaroonKey
    where
        T: AsRef<[u8; 32]> + ?Sized,
        U: AsRef<[u8]> + ?Sized,
    {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(key.as_ref())
            .expect("HMAC can take key of any size");
        mac.update(text.as_ref());
        let result = mac.finalize().into_bytes();

        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&result);
        MacaroonKey::from(key_bytes)
    }

    pub fn hmac2<T, U>(key: &T, text1: &U, text2: &U) -> MacaroonKey
    where
        T: AsRef<[u8; 32]> + ?Sized,
        U: AsRef<[u8]> + ?Sized,
    {
        let tmp1 = Self::hmac(key, text1);
        let tmp2 = Self::hmac(key, text2);
        let tmp = [tmp1.as_ref() as &[u8], tmp2.as_ref() as &[u8]].concat();
        Self::hmac(key, &tmp)
    }

    pub fn encrypt_key<T>(key: &T, plaintext: &T) -> Vec<u8>
    where
        T: AsRef<[u8; 32]> + ?Sized,
    {
        let cipher = XSalsa20Poly1305::new(AeadKey::from_slice(key.as_ref()));

        // Generate a random 24-byte nonce
        let mut nonce_bytes = [0u8; 24];
        Self::fill_random(&mut nonce_bytes);
        let nonce = Nonce::from(nonce_bytes);

        let ciphertext = cipher
            .encrypt(&nonce, plaintext.as_ref() as &[u8])
            .expect("encryption should not fail");

        // nonce || ciphertext (matches libmacaroons secretbox format)
        let mut result = Vec::with_capacity(24 + ciphertext.len());
        result.extend_from_slice(&nonce);
        result.extend_from_slice(&ciphertext);
        result
    }

    pub fn decrypt_key<T, U>(key: &T, data: &U) -> Result<MacaroonKey>
    where
        T: AsRef<[u8; 32]> + ?Sized,
        U: AsRef<[u8]> + ?Sized,
    {
        let raw_data: &[u8] = data.as_ref();

        // XSalsa20Poly1305: 24 byte nonce + 16 byte tag = minimum 40 bytes
        const NONCE_SIZE: usize = 24;
        const TAG_SIZE: usize = 16;

        if raw_data.len() < NONCE_SIZE + TAG_SIZE {
            error!(
                "crypto::decrypt: Encrypted data too short (len={})",
                raw_data.len()
            );
            return Err(MacaroonError::CryptoError("encrypted data too short"));
        }

        let nonce = Nonce::from_slice(&raw_data[..NONCE_SIZE]);
        let ciphertext = &raw_data[NONCE_SIZE..];

        let cipher = XSalsa20Poly1305::new(AeadKey::from_slice(key.as_ref()));

        match cipher.decrypt(nonce, ciphertext) {
            Ok(plaintext) => {
                if plaintext.len() != 32 {
                    return Err(MacaroonError::CryptoError(
                        "decrypted key has wrong length (expected 32 bytes)",
                    ));
                }

                let mut key_bytes = [0u8; 32];
                key_bytes.copy_from_slice(&plaintext);
                Ok(MacaroonKey::from(key_bytes))
            }
            Err(_) => {
                error!(
                    "crypto::decrypt: Decryption failed (data len={})",
                    raw_data.len()
                );
                Err(MacaroonError::CryptoError("failed to decrypt ciphertext"))
            }
        }
    }

    pub fn generate_random_key() -> MacaroonKey {
        let mut key_bytes = [0u8; 32];
        Self::fill_random(&mut key_bytes);
        MacaroonKey::from(key_bytes)
    }

    fn fill_random(buf: &mut [u8]) {
        #[cfg(target_arch = "wasm32")]
        {
            getrandom::getrandom(buf).expect("failed to generate random bytes");
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            rand::thread_rng().fill_bytes(buf);
        }
    }
}

#[cfg(test)]
mod test {
    use super::{MacaroonKey, RustCryptoBackend};

    #[test]
    fn test_encrypt_decrypt() {
        let mut secret_bytes = [0u8; 32];
        secret_bytes[..24].copy_from_slice(b"This is my encrypted key");
        let secret = MacaroonKey::from(secret_bytes);

        let mut key_bytes = [0u8; 32];
        key_bytes[..21].copy_from_slice(b"This is my secret key");
        let key = MacaroonKey::from(key_bytes);

        let encrypted = RustCryptoBackend::encrypt_key(&key, &secret);
        let decrypted = RustCryptoBackend::decrypt_key(&key, &encrypted).unwrap();
        assert_eq!(secret, decrypted);
    }

    #[test]
    fn test_hmac() {
        let key = MacaroonKey::from([1u8; 32]);
        let message = b"test message";

        let result1 = RustCryptoBackend::hmac(&key, message);
        let result2 = RustCryptoBackend::hmac(&key, message);

        // HMAC should be deterministic
        assert_eq!(result1, result2);

        // Should be different with different key
        let key2 = MacaroonKey::from([2u8; 32]);
        let result3 = RustCryptoBackend::hmac(&key2, message);
        assert_ne!(result1, result3);
    }

    #[test]
    fn test_hmac2() {
        let key = MacaroonKey::from([1u8; 32]);
        let text1 = b"first";
        let text2 = b"second";

        let result = RustCryptoBackend::hmac2(&key, text1 as &[u8], text2 as &[u8]);

        // Should be same as HMAC of concatenated individual HMACs
        let tmp1 = RustCryptoBackend::hmac(&key, text1);
        let tmp2 = RustCryptoBackend::hmac(&key, text2);
        let tmp = [tmp1.as_ref() as &[u8], tmp2.as_ref() as &[u8]].concat();
        let expected = RustCryptoBackend::hmac(&key, &tmp);

        assert_eq!(result, expected);
    }

    #[test]
    fn test_random_key_generation() {
        let key1 = RustCryptoBackend::generate_random_key();
        let key2 = RustCryptoBackend::generate_random_key();

        // Keys should be different
        assert_ne!(key1, key2);

        // Keys should not be all zeros
        assert_ne!(key1.as_ref() as &[u8; 32], &[0u8; 32]);
        assert_ne!(key2.as_ref() as &[u8; 32], &[0u8; 32]);
    }
}
