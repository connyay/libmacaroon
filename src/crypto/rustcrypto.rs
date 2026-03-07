//! RustCrypto cryptographic backend implementation
//!
//! This backend uses pure Rust implementations from the RustCrypto project,
//! making it compatible with WebAssembly and other constrained environments.

use crate::crypto::{CryptoBackend, MacaroonKey};
use crate::error::MacaroonError;
use crate::Result;
use xsalsa20poly1305::{
    aead::{Aead, KeyInit},
    XSalsa20Poly1305, Nonce, Key as AeadKey
};
use hmac::{Hmac, Mac};
#[cfg(not(target_arch = "wasm32"))]
use rand::RngCore;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// RustCrypto backend implementation
pub struct RustCryptoBackend;

impl CryptoBackend for RustCryptoBackend {
    fn init() -> Result<()> {
        // RustCrypto doesn't require initialization like sodiumoxide
        // Just ensure that getrandom is available for WASM
        #[cfg(target_arch = "wasm32")]
        {
            // Test that random generation works
            let mut test_bytes = [0u8; 4];
            getrandom::getrandom(&mut test_bytes)
                .map_err(|_| MacaroonError::InitializationError)?;
        }
        Ok(())
    }
    
    fn hmac<T, U>(key: &T, text: &U) -> MacaroonKey
    where
        T: AsRef<[u8; 32]> + ?Sized,
        U: AsRef<[u8]> + ?Sized,
    {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(key.as_ref())
            .expect("HMAC can take key of any size");
        mac.update(text.as_ref());
        let result = mac.finalize().into_bytes();
        
        // Convert generic array to [u8; 32]
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&result);
        MacaroonKey::from(key_bytes)
    }
    
    fn hmac2<T, U>(key: &T, text1: &U, text2: &U) -> MacaroonKey
    where
        T: AsRef<[u8; 32]> + ?Sized,
        U: AsRef<[u8]> + ?Sized,
    {
        let tmp1 = Self::hmac(key, text1);
        let tmp2 = Self::hmac(key, text2);
        let tmp = [tmp1.as_ref() as &[u8], tmp2.as_ref() as &[u8]].concat();
        Self::hmac(key, &tmp)
    }
    
    fn encrypt_key<T>(key: &T, plaintext: &T) -> Vec<u8>
    where
        T: AsRef<[u8; 32]> + ?Sized,
    {
        let cipher = XSalsa20Poly1305::new(AeadKey::from_slice(key.as_ref()));

        // Generate a random 24-byte nonce
        let mut nonce_bytes = [0u8; 24];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce_bytes);
        let nonce = Nonce::from(nonce_bytes);
        
        // Encrypt the plaintext
        let ciphertext = cipher.encrypt(&nonce, plaintext.as_ref() as &[u8])
            .expect("encryption should not fail");
        
        // Prepend nonce to ciphertext (like sodiumoxide secretbox format)
        let mut result = Vec::with_capacity(24 + ciphertext.len());
        result.extend_from_slice(&nonce);
        result.extend_from_slice(&ciphertext);
        result
    }
    
    fn decrypt_key<T, U>(key: &T, data: &U) -> Result<MacaroonKey>
    where
        T: AsRef<[u8; 32]> + ?Sized,
        U: AsRef<[u8]> + ?Sized,
    {
        let raw_data: &[u8] = data.as_ref();
        
        // XSalsa20Poly1305: 24 byte nonce + 16 byte tag = minimum 40 bytes
        const NONCE_SIZE: usize = 24;
        const TAG_SIZE: usize = 16;

        if raw_data.len() < NONCE_SIZE + TAG_SIZE {
            error!("crypto::decrypt: Encrypted data {:?} too short", raw_data);
            return Err(MacaroonError::CryptoError("encrypted data too short"));
        }

        // Extract nonce and ciphertext
        let nonce = Nonce::from_slice(&raw_data[..NONCE_SIZE]);
        let ciphertext = &raw_data[NONCE_SIZE..];

        // Create cipher and decrypt
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
                    "crypto::decrypt: Unknown decryption error decrypting {:?}",
                    raw_data
                );
                Err(MacaroonError::CryptoError("failed to decrypt ciphertext"))
            }
        }
    }
    
    fn generate_random_key() -> MacaroonKey {
        let mut key_bytes = [0u8; 32];
        
        #[cfg(target_arch = "wasm32")]
        {
            // Use getrandom for WASM environments
            getrandom::getrandom(&mut key_bytes)
                .expect("failed to generate random bytes");
        }
        
        #[cfg(not(target_arch = "wasm32"))]
        {
            // Use rand::thread_rng for native environments
            rand::thread_rng().fill_bytes(&mut key_bytes);
        }
        
        MacaroonKey::from(key_bytes)
    }
}

#[cfg(test)]
mod test {
    use super::{RustCryptoBackend, CryptoBackend, MacaroonKey};

    #[test]
    fn test_encrypt_decrypt() {
        // Test encryption/decryption roundtrip
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