//! SodiumOxide cryptographic backend implementation

use crate::crypto::{CryptoBackend, MacaroonKey};
use crate::error::MacaroonError;
use crate::Result;
use sodiumoxide::crypto::auth::hmacsha256::{authenticate, gen_key, Key, Tag};
use sodiumoxide::crypto::secretbox;

/// SodiumOxide backend implementation
pub struct SodiumOxideBackend;

impl CryptoBackend for SodiumOxideBackend {
    fn init() -> Result<()> {
        sodiumoxide::init().map_err(|_| MacaroonError::InitializationError)
    }
    
    fn hmac<T, U>(key: &T, text: &U) -> MacaroonKey
    where
        T: AsRef<[u8; 32]> + ?Sized,
        U: AsRef<[u8]> + ?Sized,
    {
        let Tag(result_bytes) = authenticate(text.as_ref(), &Key(*key.as_ref()));
        MacaroonKey::from(result_bytes)
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
        let nonce = secretbox::gen_nonce();
        let encrypted = secretbox::seal(plaintext.as_ref(), &nonce, &secretbox::Key(*key.as_ref()));
        let mut ret: Vec<u8> = Vec::new();
        ret.extend(&nonce.0);
        ret.extend(encrypted);
        ret
    }
    
    fn decrypt_key<T, U>(key: &T, data: &U) -> Result<MacaroonKey>
    where
        T: AsRef<[u8; 32]> + ?Sized,
        U: AsRef<[u8]> + ?Sized,
    {
        let raw_data: &[u8] = data.as_ref();
        if raw_data.len() <= secretbox::NONCEBYTES + secretbox::MACBYTES {
            error!("crypto::decrypt: Encrypted data {:?} too short", raw_data);
            return Err(MacaroonError::CryptoError("encrypted data too short"));
        }
        let mut nonce: [u8; secretbox::NONCEBYTES] = [0; secretbox::NONCEBYTES];
        nonce.clone_from_slice(&raw_data[..secretbox::NONCEBYTES]);
        let mut temp: Vec<u8> = Vec::new();
        temp.extend(&raw_data[secretbox::NONCEBYTES..]);
        let ciphertext = temp.as_slice();
        match secretbox::open(
            ciphertext,
            &secretbox::Nonce(nonce),
            &secretbox::Key(*key.as_ref()),
        ) {
            Ok(plaintext) => Ok(Key::from_slice(&plaintext)
                .ok_or(MacaroonError::CryptoError(
                    "supplied key has wrong length (expected 32 bytes)",
                ))?
                .into()),
            Err(()) => {
                error!(
                    "crypto::decrypt: Unknown decryption error decrypting {:?}",
                    raw_data
                );
                Err(MacaroonError::CryptoError("failed to decrypt ciphertext"))
            }
        }
    }
    
    fn generate_random_key() -> MacaroonKey {
        MacaroonKey::from(gen_key().0)
    }
}

// Support for converting from sodiumoxide Key to MacaroonKey
impl From<Key> for MacaroonKey {
    fn from(k: Key) -> Self {
        MacaroonKey::from(k.0)
    }
}

#[cfg(test)]
mod test {
    use super::{SodiumOxideBackend, CryptoBackend, MacaroonKey};

    #[test]
    fn test_encrypt_decrypt() {
        // NOTE: these are keys as byte sequences, not generated via HMAC
        let mut secret_bytes = [0u8; 32];
        secret_bytes[..24].copy_from_slice(b"This is my encrypted key");
        let secret = MacaroonKey::from(secret_bytes);
        
        let mut key_bytes = [0u8; 32];
        key_bytes[..21].copy_from_slice(b"This is my secret key");
        let key = MacaroonKey::from(key_bytes);
        
        let encrypted = SodiumOxideBackend::encrypt_key(&key, &secret);
        let decrypted = SodiumOxideBackend::decrypt_key(&key, &encrypted).unwrap();
        assert_eq!(secret, decrypted);
    }
}
