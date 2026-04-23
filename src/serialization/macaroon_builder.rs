use crate::caveat::Caveat;
use crate::error::MacaroonError;
use crate::{ByteString, Macaroon, MacaroonKey, Result, MAX_CAVEATS};

pub struct MacaroonBuilder {
    identifier: ByteString,
    location: Option<String>,
    signature: MacaroonKey,
    caveats: Vec<Caveat>,
}

impl MacaroonBuilder {
    pub fn new() -> MacaroonBuilder {
        MacaroonBuilder {
            identifier: Default::default(),
            location: None,
            // Zero-valued sentinel: `build()` rejects a signature that was never
            // set, which `is_empty()` detects only if the initial value is zero.
            signature: MacaroonKey::from([0u8; 32]),
            caveats: Default::default(),
        }
    }

    pub fn set_identifier(&mut self, identifier: ByteString) {
        self.identifier = identifier;
    }

    pub fn set_location(&mut self, location: &str) {
        self.location = Some((*location).to_string());
    }

    pub fn has_location(&self) -> bool {
        self.location.is_some()
    }

    pub fn set_signature(&mut self, signature: &[u8]) {
        self.signature.copy_from_slice(signature);
    }

    pub fn add_caveat(&mut self, caveat: Caveat) -> Result<()> {
        if self.caveats.len() >= MAX_CAVEATS {
            return Err(MacaroonError::TooManyCaveats);
        }
        self.caveats.push(caveat);
        Ok(())
    }

    pub fn build(&self) -> Result<Macaroon> {
        if self.identifier.0.is_empty() {
            return Err(MacaroonError::IncompleteMacaroon("no identifier found"));
        }
        if self.signature.is_empty() {
            return Err(MacaroonError::IncompleteMacaroon("no signature found"));
        }

        Ok(Macaroon {
            identifier: self.identifier.clone(),
            location: self.location.clone(),
            signature: self.signature.clone(),
            caveats: self.caveats.clone(),
        })
    }
}
