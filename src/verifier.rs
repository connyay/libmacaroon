use crate::crypto;
use crate::{ByteString, Caveat, Macaroon, MacaroonError, MacaroonKey, Result};
use std::collections::BTreeSet;
use std::collections::HashMap;

const MAX_VERIFICATION_DEPTH: usize = 32;

/// Boxed predicate for `satisfy_general`. The `Send + Sync` bound lets the
/// resulting [`Verifier`] itself be `Send + Sync`, so callers can build one
/// at startup and share `&Verifier` across request handlers (the typical
/// HTTP server pattern). The tax on user closures is small — most don't
/// capture non-thread-safe state.
type GeneralVerifier = Box<dyn Fn(&[u8]) -> bool + Send + Sync>;

#[derive(Default)]
pub struct Verifier {
    exact: BTreeSet<ByteString>,
    general: Vec<GeneralVerifier>,
}

impl Verifier {
    pub fn verify(&self, m: &Macaroon, key: &MacaroonKey, discharges: &[Macaroon]) -> Result<()> {
        // Reject duplicate-ID discharges explicitly rather than silently
        // dropping one when collecting into a HashMap. A well-formed set of
        // discharges has exactly one entry per third-party caveat ID; two
        // entries with the same ID almost always indicates a caller bug
        // (e.g., appending new discharges without de-duplicating), and
        // letting it through silently could hide a stale discharge being
        // used in place of a fresh one.
        let mut discharge_set: HashMap<ByteString, Macaroon> =
            HashMap::with_capacity(discharges.len());
        for d in discharges {
            if discharge_set.contains_key(&d.identifier) {
                return Err(MacaroonError::CaveatNotSatisfied(format!(
                    "duplicate discharge macaroons with identifier {:?}",
                    String::from_utf8_lossy(&d.identifier.0)
                )));
            }
            discharge_set.insert(d.identifier.clone(), d.clone());
        }
        self.verify_with_sig(&m.signature, m, key, &mut discharge_set, 0)?;
        // Now check that all discharges were used
        if !discharge_set.is_empty() {
            return Err(MacaroonError::DischargeNotUsed);
        }
        Ok(())
    }

    fn verify_with_sig(
        &self,
        root_sig: &MacaroonKey,
        m: &Macaroon,
        key: &MacaroonKey,
        discharge_set: &mut HashMap<ByteString, Macaroon>,
        depth: usize,
    ) -> Result<()> {
        if depth > MAX_VERIFICATION_DEPTH {
            return Err(MacaroonError::CaveatNotSatisfied(
                "discharge verification exceeded maximum depth".to_string(),
            ));
        }
        let mut sig = crypto::hmac(key, m.identifier());
        for c in m.caveats() {
            sig = match c {
                Caveat::ThirdParty(tp) => {
                    let caveat_key = crypto::decrypt_key(&sig, tp.verifier_id())?;
                    let dm = discharge_set.remove(tp.id()).ok_or_else(|| MacaroonError::CaveatNotSatisfied("no discharge macaroon found (or discharge has already been used) for third-party caveat".to_string()))?;
                    self.verify_with_sig(root_sig, &dm, &caveat_key, discharge_set, depth + 1)?;
                    c.sign(&sig)
                }
                Caveat::FirstParty(fp) => {
                    if !(self.exact.contains(fp.predicate()) || self.verify_general(fp.predicate()))
                    {
                        return Err(MacaroonError::CaveatNotSatisfied(format!(
                            "first party caveat not satisfied: {}",
                            String::from_utf8_lossy(fp.predicate())
                        )));
                    }
                    c.sign(&sig)
                }
            };
        }
        // If the root sig equals the newly generated sig, that means we reached
        // the end of the line and we are ok to return
        if root_sig == &sig {
            return Ok(());
        }
        // Check the bound signature equals the signature of the discharge
        // macaroon
        let zero_key: MacaroonKey = [0; 32].into();
        let bound_sig = crypto::hmac2(&zero_key, root_sig, &sig);
        if bound_sig != m.signature {
            return Err(MacaroonError::InvalidSignature);
        }
        Ok(())
    }

    pub fn satisfy_exact(&mut self, b: impl AsRef<[u8]>) {
        self.exact.insert(ByteString(b.as_ref().to_vec()));
    }

    pub fn satisfy_general<F: Fn(&[u8]) -> bool + Send + Sync + 'static>(&mut self, f: F) {
        self.general.push(Box::new(f))
    }

    fn verify_general(&self, value: &[u8]) -> bool {
        self.general.iter().any(|f| f(value))
    }
}

#[cfg(test)]
mod tests {
    use super::Verifier;
    use crate::{Macaroon, MacaroonError, MacaroonKey};

    #[test]
    fn test_simple_macaroon() {
        let key = MacaroonKey::generate(b"this is the key");
        let macaroon = Macaroon::create(None, &key, "testing").unwrap();
        let verifier = Verifier::default();
        verifier.verify(&macaroon, &key, &[]).unwrap();
    }

    #[test]
    fn test_simple_macaroon_bad_verifier_key() {
        let macaroon = Macaroon::create(None, &MacaroonKey::generate(b"key"), "testing").unwrap();
        let key = MacaroonKey::generate(b"this is not the key");
        let verifier = Verifier::default();
        verifier.verify(&macaroon, &key, &[]).unwrap_err();
    }

    #[test]
    fn test_macaroon_exact_caveat() {
        let key = MacaroonKey::generate(b"this is the key");
        let mut macaroon = Macaroon::create(None, &key, "testing").unwrap();
        macaroon
            .add_first_party_caveat("account = 3735928559")
            .unwrap();
        let mut verifier = Verifier::default();
        verifier.satisfy_exact("account = 3735928559");
        verifier.verify(&macaroon, &key, &[]).unwrap()
    }

    #[test]
    fn test_macaroon_exact_caveat_wrong_verifier() {
        let key = MacaroonKey::generate(b"this is the key");
        let mut macaroon = Macaroon::create(None, &key, "testing").unwrap();
        macaroon
            .add_first_party_caveat("account = 3735928559")
            .unwrap();
        let mut verifier = Verifier::default();
        verifier.satisfy_exact("account = 0000000000");
        verifier.verify(&macaroon, &key, &[]).unwrap_err();
    }

    #[test]
    fn test_macaroon_exact_caveat_wrong_context() {
        let key = MacaroonKey::generate(b"this is the key");
        let mut macaroon = Macaroon::create(None, &key, "testing").unwrap();
        macaroon
            .add_first_party_caveat("account = 3735928559")
            .unwrap();
        let verifier = Verifier::default();
        verifier.verify(&macaroon, &key, &[]).unwrap_err();
    }

    #[test]
    fn test_macaroon_two_exact_caveats() {
        let key = MacaroonKey::generate(b"this is the key");
        let mut macaroon = Macaroon::create(None, &key, "testing").unwrap();
        macaroon
            .add_first_party_caveat("account = 3735928559")
            .unwrap();
        macaroon.add_first_party_caveat("user = alice").unwrap();
        let mut verifier = Verifier::default();
        verifier.satisfy_exact("account = 3735928559");
        verifier.satisfy_exact("user = alice");
        verifier.verify(&macaroon, &key, &[]).unwrap()
    }

    #[test]
    fn test_macaroon_two_exact_caveats_incomplete_verifier() {
        let key = MacaroonKey::generate(b"this is the key");
        let mut macaroon = Macaroon::create(None, &key, "testing").unwrap();
        macaroon
            .add_first_party_caveat("account = 3735928559")
            .unwrap();
        macaroon.add_first_party_caveat("user = alice").unwrap();
        let mut verifier = Verifier::default();
        verifier.satisfy_exact("account = 3735928559");
        verifier.verify(&macaroon, &key, &[]).unwrap_err();
        let mut verifier = Verifier::default();
        verifier.satisfy_exact("user = alice");
        verifier.verify(&macaroon, &key, &[]).unwrap_err();
    }

    /// Test helper that parses `"time > YYYY-MM-DDTHH:MM+ZZZZ"` caveats.
    ///
    /// Uses a fixed reference instead of the real clock so the tests are
    /// deterministic and we avoid pulling in a date-parsing dev-dep. ISO
    /// 8601 fixed-width timestamps compare correctly lexicographically, so
    /// byte comparison is sufficient.
    fn after_time_verifier(caveat: &[u8]) -> bool {
        const REFERENCE_NOW: &[u8] = b"2024-01-01T00:00+0000";
        const PREFIX: &[u8] = b"time > ";
        if !caveat.starts_with(PREFIX) {
            return false;
        }
        let when = &caveat[PREFIX.len()..];
        when.len() == REFERENCE_NOW.len() && when < REFERENCE_NOW
    }

    #[test]
    fn test_macaroon_two_exact_and_one_general_caveat() {
        let key = MacaroonKey::generate(b"this is the key");
        let mut macaroon = Macaroon::create(Some("http://example.org/"), &key, "keyid").unwrap();
        macaroon
            .add_first_party_caveat("account = 3735928559")
            .unwrap();
        macaroon.add_first_party_caveat("user = alice").unwrap();
        macaroon
            .add_first_party_caveat("time > 2010-01-01T00:00+0000")
            .unwrap();
        let mut verifier = Verifier::default();
        verifier.satisfy_exact("account = 3735928559");
        verifier.satisfy_exact("user = alice");
        verifier.satisfy_general(after_time_verifier);
        verifier.verify(&macaroon, &key, &[]).unwrap()
    }

    #[test]
    fn test_macaroon_two_exact_and_one_general_fails_general() {
        let key = MacaroonKey::generate(b"this is the key");
        let mut macaroon = Macaroon::create(Some("http://example.org/"), &key, "keyid").unwrap();
        macaroon
            .add_first_party_caveat("account = 3735928559")
            .unwrap();
        macaroon.add_first_party_caveat("user = alice").unwrap();
        macaroon
            .add_first_party_caveat("time > 3010-01-01T00:00+0000")
            .unwrap();
        let mut verifier = Verifier::default();
        verifier.satisfy_exact("account = 3735928559");
        verifier.satisfy_exact("user = alice");
        verifier.satisfy_general(after_time_verifier);
        verifier.verify(&macaroon, &key, &[]).unwrap_err();
    }

    #[test]
    fn test_macaroon_two_exact_and_one_general_incomplete_verifier() {
        let key = MacaroonKey::generate(b"this is the key");
        let mut macaroon = Macaroon::create(Some("http://example.org/"), &key, "keyid").unwrap();
        macaroon
            .add_first_party_caveat("account = 3735928559")
            .unwrap();
        macaroon.add_first_party_caveat("user = alice").unwrap();
        macaroon
            .add_first_party_caveat("time > 2010-01-01T00:00+0000")
            .unwrap();
        let mut verifier = Verifier::default();
        verifier.satisfy_exact("account = 3735928559");
        verifier.satisfy_exact("user = alice");
        verifier.verify(&macaroon, &key, &[]).unwrap_err();
    }

    #[test]
    fn test_macaroon_third_party_caveat() {
        let root_key = MacaroonKey::generate(b"this is the key");
        let another_key = MacaroonKey::generate(b"this is another key");
        let mut macaroon =
            Macaroon::create(Some("http://example.org/"), &root_key, "keyid").unwrap();
        macaroon
            .add_third_party_caveat("http://auth.mybank/", &another_key, "other keyid")
            .unwrap();
        let mut discharge =
            Macaroon::create(Some("http://auth.mybank/"), &another_key, "other keyid").unwrap();
        discharge
            .add_first_party_caveat("time > 2010-01-01T00:00+0000")
            .unwrap();
        macaroon.bind(&mut discharge);
        let mut verifier = Verifier::default();
        verifier.satisfy_general(after_time_verifier);
        verifier.verify(&macaroon, &root_key, &[discharge]).unwrap()
    }

    #[test]
    fn test_macaroon_third_party_caveat_with_cycle() {
        let root_key = MacaroonKey::generate(b"this is the key");
        let another_key = MacaroonKey::generate(b"this is another key");
        let mut macaroon =
            Macaroon::create(Some("http://example.org/"), &root_key, "keyid").unwrap();
        macaroon
            .add_third_party_caveat("http://auth.mybank/", &another_key, "other keyid")
            .unwrap();
        let mut discharge =
            Macaroon::create(Some("http://auth.mybank/"), &another_key, "other keyid").unwrap();
        discharge
            .add_third_party_caveat("http://auth.mybank/", &another_key, "other keyid")
            .unwrap();
        macaroon.bind(&mut discharge);
        let mut verifier = Verifier::default();
        verifier.satisfy_general(after_time_verifier);
        verifier
            .verify(&macaroon, &root_key, &[discharge])
            .unwrap_err();
    }

    #[test]
    fn test_macaroon_third_party_unsatisfied() {
        let root_key = MacaroonKey::generate(b"this is the key");
        let another_key = MacaroonKey::generate(b"this is another key");
        let mut macaroon =
            Macaroon::create(Some("http://example.org/"), &root_key, "keyid").unwrap();

        // with no caveats, should verify fine
        let verifier = Verifier::default();
        verifier.verify(&macaroon, &root_key, &[]).unwrap();

        // add a third party caveat but no satisfier, should fail
        macaroon
            .add_third_party_caveat("http://auth.mybank/", &another_key, "other keyid")
            .unwrap();
        assert!(matches!(
            verifier.verify(&macaroon, &root_key, &[]),
            Err(MacaroonError::CaveatNotSatisfied(_))
        ));
    }

    #[test]
    fn test_duplicate_discharges_rejected() {
        // Two discharge macaroons with the same identifier must be rejected
        // rather than silently de-duplicated, so callers can't accidentally
        // substitute a stale discharge for a fresh one.
        let root_key = MacaroonKey::generate(b"root");
        let cav_key = MacaroonKey::generate(b"caveat");
        let mut mac = Macaroon::create(Some("http://example.org/"), &root_key, "keyid").unwrap();
        mac.add_third_party_caveat("http://auth/", &cav_key, "other keyid")
            .unwrap();

        let mut d1 = Macaroon::create(Some("http://auth/"), &cav_key, "other keyid").unwrap();
        let mut d2 = Macaroon::create(Some("http://auth/"), &cav_key, "other keyid").unwrap();
        mac.bind(&mut d1);
        mac.bind(&mut d2);

        let verifier = Verifier::default();
        let err = verifier.verify(&mac, &root_key, &[d1, d2]).unwrap_err();
        match err {
            MacaroonError::CaveatNotSatisfied(s) => {
                assert!(s.contains("duplicate"), "unexpected message: {}", s);
            }
            other => panic!("expected CaveatNotSatisfied, got {:?}", other),
        }
    }
}
