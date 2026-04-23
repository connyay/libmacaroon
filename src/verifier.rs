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
        let mut discharge_set = discharges
            .iter()
            .map(|d| (d.identifier.clone(), d.clone()))
            .collect::<HashMap<ByteString, Macaroon>>();
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
    extern crate time;

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

    fn after_time_verifier(caveat: &[u8]) -> bool {
        if !caveat.starts_with(b"time > ") {
            return false;
        }
        let strcaveat = match std::str::from_utf8(caveat) {
            Ok(s) => s,
            Err(_) => return false,
        };

        let format = time::format_description::parse(
            "[year]-[month]-[day]T[hour]:[minute][offset_hour sign:mandatory][offset_minute]",
        )
        .unwrap();
        match time::OffsetDateTime::parse(&strcaveat[7..], &format) {
            Ok(compare) => time::OffsetDateTime::now_utc() > compare,
            Err(_) => false,
        }
    }

    #[test]
    fn test_macaroon_two_exact_and_one_general_caveat() {
        let key = MacaroonKey::generate(b"this is the key");
        let mut macaroon =
            Macaroon::create(Some("http://example.org/".into()), &key, "keyid").unwrap();
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
        let mut macaroon =
            Macaroon::create(Some("http://example.org/".into()), &key, "keyid").unwrap();
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
        let mut macaroon =
            Macaroon::create(Some("http://example.org/".into()), &key, "keyid").unwrap();
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
            Macaroon::create(Some("http://example.org/".into()), &root_key, "keyid").unwrap();
        macaroon
            .add_third_party_caveat("http://auth.mybank/", &another_key, "other keyid")
            .unwrap();
        let mut discharge = Macaroon::create(
            Some("http://auth.mybank/".into()),
            &another_key,
            "other keyid",
        )
        .unwrap();
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
            Macaroon::create(Some("http://example.org/".into()), &root_key, "keyid").unwrap();
        macaroon
            .add_third_party_caveat("http://auth.mybank/", &another_key, "other keyid")
            .unwrap();
        let mut discharge = Macaroon::create(
            Some("http://auth.mybank/".into()),
            &another_key,
            "other keyid",
        )
        .unwrap();
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
            Macaroon::create(Some("http://example.org/".into()), &root_key, "keyid").unwrap();

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
}
