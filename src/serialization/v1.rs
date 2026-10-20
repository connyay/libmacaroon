use crate::caveat::{Caveat, CaveatBuilder};
use crate::error::MacaroonError;
use crate::serialization::macaroon_builder::MacaroonBuilder;
use crate::{ByteString, Macaroon, Result, URL_SAFE, check_field_size};
use base64::Engine as _;
use log::debug;
use std::str;

// Version 1 fields
const LOCATION: &str = "location";
const IDENTIFIER: &str = "identifier";
const SIGNATURE: &str = "signature";
const CID: &str = "cid";
const VID: &str = "vid";
const CL: &str = "cl";

const HEADER_SIZE: usize = 4;
// The four-hex-digit size header covers the whole packet, including itself.
const MAX_PACKET_SIZE: usize = 0xFFFF;

fn serialize_as_packet<'r>(tag: &'r str, value: &'r [u8]) -> Result<Vec<u8>> {
    let size = HEADER_SIZE + 2 + tag.len() + value.len();
    // The size header would otherwise wrap silently past 0xFFFF and emit a
    // corrupt token. Reachable only for fields within `tag.len() + 6` bytes
    // of MAX_FIELD_SIZE_BYTES, which V2/V2JSON can serialize but V1 cannot.
    if size > MAX_PACKET_SIZE {
        return Err(MacaroonError::FieldTooLarge {
            field: "v1 packet",
            size,
        });
    }
    let mut packet: Vec<u8> = Vec::new();
    packet.extend(packet_header(size));
    packet.extend_from_slice(tag.as_bytes());
    packet.extend_from_slice(b" ");
    packet.extend_from_slice(value);
    packet.extend_from_slice(b"\n");

    Ok(packet)
}

fn packet_header(size: usize) -> [u8; 4] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    [
        HEX[(size >> 12) & 15],
        HEX[(size >> 8) & 15],
        HEX[(size >> 4) & 15],
        HEX[size & 15],
    ]
}

pub fn serialize_binary(macaroon: &Macaroon) -> Result<Vec<u8>> {
    let mut serialized: Vec<u8> = Vec::new();
    if let Some(location) = macaroon.location() {
        serialized.extend(serialize_as_packet(LOCATION, location.as_bytes())?);
    };
    serialized.extend(serialize_as_packet(IDENTIFIER, macaroon.identifier())?);
    for c in macaroon.caveats() {
        match c {
            Caveat::FirstParty(fp) => {
                serialized.extend(serialize_as_packet(CID, fp.predicate())?);
            }
            Caveat::ThirdParty(tp) => {
                serialized.extend(serialize_as_packet(CID, tp.id())?);
                serialized.extend(serialize_as_packet(VID, tp.verifier_id())?);
                serialized.extend(serialize_as_packet(CL, tp.location().as_bytes())?)
            }
        }
    }
    serialized.extend(serialize_as_packet(
        SIGNATURE,
        macaroon.signature().as_ref(),
    )?);
    Ok(serialized)
}

pub fn serialize(macaroon: &Macaroon) -> Result<String> {
    let buf = serialize_binary(macaroon)?;
    Ok(URL_SAFE.encode(&buf))
}

/// Splits the packet at the front of `data` into its key and value,
/// returning them with the rest of the input.
///
/// Only the encoding the serializer writes is accepted, so a packet has one
/// byte representation: a size of exactly four lowercase hex digits covering
/// the whole packet, then `key SP value LF`.
fn next_packet(data: &[u8]) -> Result<(&str, &[u8], &[u8])> {
    if data.len() < HEADER_SIZE {
        return Err(MacaroonError::DeserializationError(
            "packet chunk too small to decode".to_string(),
        ));
    }
    let mut size: usize = 0;
    for &digit in &data[..HEADER_SIZE] {
        let nibble = match digit {
            b'0'..=b'9' => digit - b'0',
            b'a'..=b'f' => digit - b'a' + 10,
            _ => {
                return Err(MacaroonError::DeserializationError(
                    "packet size is not four lowercase hex digits".to_string(),
                ));
            }
        };
        size = (size << 4) | usize::from(nibble);
    }
    if size > data.len() {
        return Err(MacaroonError::DeserializationError(
            "packet chunk size larger than token".to_string(),
        ));
    }
    // The shortest packet is the header followed by " \n".
    if size < HEADER_SIZE + 2 {
        return Err(MacaroonError::DeserializationError(
            "packet chunk size too small".to_string(),
        ));
    }
    let (packet, rest) = data.split_at(size);
    let Some((&b'\n', body)) = packet[HEADER_SIZE..].split_last() else {
        return Err(MacaroonError::DeserializationError(
            "packet not terminated by a newline".to_string(),
        ));
    };
    let index = split_index(body)?;
    let value = &body[index + 1..];
    check_field_size("v1 packet", value.len())?;
    Ok((str::from_utf8(&body[..index])?, value, rest))
}

fn split_index(packet: &[u8]) -> Result<usize> {
    match packet.iter().position(|&r| r == b' ') {
        Some(index) => Ok(index),
        None => Err(MacaroonError::DeserializationError(String::from(
            "Key/value error",
        ))),
    }
}

/// Takes a binary token (not base64-encoded)
///
/// Packets must come in the order the serializer writes them,
/// `location? identifier (cid (vid cl)?)* signature`, and are read one at a
/// time, so the caveat cap bounds memory and no packet goes unread.
pub fn deserialize(data: &[u8]) -> Result<Macaroon> {
    let mut builder: MacaroonBuilder = MacaroonBuilder::new();
    let (mut key, mut value, mut remaining) = next_packet(data)?;
    if key == LOCATION {
        builder.set_location(str::from_utf8(value)?);
        (key, value, remaining) = next_packet(remaining)?;
    }
    if key != IDENTIFIER {
        return Err(MacaroonError::DeserializationError(String::from(
            "identifier packet not found",
        )));
    }
    builder.set_identifier(ByteString::from(value));

    // A caveat's `cid` is held until the next packet shows whether `vid` and
    // `cl` follow it (third party) or not (first party).
    let mut caveat: Option<CaveatBuilder> = None;
    loop {
        if remaining.is_empty() {
            return Err(MacaroonError::IncompleteMacaroon("no signature found"));
        }
        (key, value, remaining) = next_packet(remaining)?;
        match key {
            CID => {
                if let Some(first_party) = caveat.take() {
                    builder.add_caveat(first_party.build()?)?;
                }
                let mut next = CaveatBuilder::new();
                next.add_id(ByteString::from(value));
                caveat = Some(next);
            }
            VID => {
                let Some(mut third_party) = caveat.take() else {
                    return Err(MacaroonError::DeserializationError(String::from(
                        "vid packet not preceded by a cid packet",
                    )));
                };
                third_party.add_verifier_id(ByteString::from(value));
                (key, value, remaining) = next_packet(remaining)?;
                if key != CL {
                    return Err(MacaroonError::DeserializationError(String::from(
                        "vid packet not followed by a cl packet",
                    )));
                }
                third_party.add_location(str::from_utf8(value)?.to_string());
                builder.add_caveat(third_party.build()?)?;
            }
            SIGNATURE => {
                if let Some(first_party) = caveat.take() {
                    builder.add_caveat(first_party.build()?)?;
                }
                if value.len() != 32 {
                    debug!(
                        "deserialize_v1: Deserialization error - signature length is {}",
                        value.len()
                    );
                    return Err(MacaroonError::DeserializationError(String::from(
                        "Illegal signature \
                         length in \
                         packet",
                    )));
                }
                builder.set_signature(value);
                // The signature must be the last packet: anything after it
                // would go unread, giving one macaroon several encodings.
                if !remaining.is_empty() {
                    return Err(MacaroonError::DeserializationError(String::from(
                        "packet found after signature",
                    )));
                }
                return builder.build();
            }
            LOCATION | IDENTIFIER | CL => {
                return Err(MacaroonError::DeserializationError(format!(
                    "unexpected {} packet",
                    key
                )));
            }
            _ => {
                return Err(MacaroonError::DeserializationError(String::from(
                    "Unknown key",
                )));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::URL_SAFE;
    use crate::{Caveat, Macaroon, MacaroonKey, STANDARD};
    use base64::Engine as _;

    #[test]
    fn test_deserialize() {
        let mut serialized = "MDAyMWxvY2F0aW9uIGh0dHA6Ly9leGFtcGxlLm9yZy8KMDAxNWlkZW50aWZpZXIga2V5aWQKMDAyZnNpZ25hdHVyZSB83ueSURxbxvUoSFgF3-myTnheKOKpkwH51xHGCeOO9wo";
        let mut signature: MacaroonKey = [
            124, 222, 231, 146, 81, 28, 91, 198, 245, 40, 72, 88, 5, 223, 233, 178, 78, 120, 94,
            40, 226, 169, 147, 1, 249, 215, 17, 198, 9, 227, 142, 247,
        ]
        .into();
        let data = URL_SAFE.decode(serialized).unwrap();
        let macaroon = super::deserialize(&data).unwrap();
        let macaroon_lib = Macaroon::deserialize(serialized).unwrap();
        assert_eq!(macaroon, macaroon_lib);
        assert!(macaroon.location().is_some());
        assert_eq!("http://example.org/", macaroon.location().unwrap());
        assert_eq!(b"keyid", macaroon.identifier());
        assert_eq!(&signature, macaroon.signature());
        serialized = "MDAyMWxvY2F0aW9uIGh0dHA6Ly9leGFtcGxlLm9yZy8KMDAxNWlkZW50aWZpZXIga2V5aWQKMDAxZGNpZCBhY2NvdW50ID0gMzczNTkyODU1OQowMDJmc2lnbmF0dXJlIPVIB_bcbt-Ivw9zBrOCJWKjYlM9v3M5umF2XaS9JZ2HCg";
        signature = [
            245, 72, 7, 246, 220, 110, 223, 136, 191, 15, 115, 6, 179, 130, 37, 98, 163, 98, 83,
            61, 191, 115, 57, 186, 97, 118, 93, 164, 189, 37, 157, 135,
        ]
        .into();
        let data = URL_SAFE.decode(serialized).unwrap();
        let macaroon = super::deserialize(&data).unwrap();
        assert!(macaroon.location().is_some());
        assert_eq!("http://example.org/", macaroon.location().unwrap());
        assert_eq!(b"keyid", macaroon.identifier());
        assert_eq!(1, macaroon.caveats().len());
        let predicate = match &macaroon.caveats()[0] {
            Caveat::FirstParty(fp) => fp.predicate().to_vec(),
            _ => vec![],
        };
        assert_eq!(b"account = 3735928559".to_vec(), predicate);
        assert_eq!(&signature, macaroon.signature());
    }

    #[test]
    fn test_deserialize_two_caveats() {
        let serialized = "MDAyMWxvY2F0aW9uIGh0dHA6Ly9leGFtcGxlLm9yZy8KMDAxNWlkZW50aWZpZXIga2V5aWQKMDAxZGNpZCBhY2NvdW50ID0gMzczNTkyODU1OQowMDE1Y2lkIHVzZXIgPSBhbGljZQowMDJmc2lnbmF0dXJlIEvpZ80eoMaya69qSpTumwWxWIbaC6hejEKpPI0OEl78Cg";
        let signature: MacaroonKey = [
            75, 233, 103, 205, 30, 160, 198, 178, 107, 175, 106, 74, 148, 238, 155, 5, 177, 88,
            134, 218, 11, 168, 94, 140, 66, 169, 60, 141, 14, 18, 94, 252,
        ]
        .into();
        let data = STANDARD.decode(serialized).unwrap();
        let macaroon = super::deserialize(&data).unwrap();
        let macaroon_lib = Macaroon::deserialize(serialized).unwrap();
        assert_eq!(macaroon, macaroon_lib);
        assert!(macaroon.location().is_some());
        assert_eq!("http://example.org/", macaroon.location().unwrap());
        assert_eq!(b"keyid", macaroon.identifier());
        assert_eq!(&signature, macaroon.signature());
        assert_eq!(2, macaroon.caveats().len());
        let predicate = match &macaroon.caveats()[0] {
            Caveat::FirstParty(fp) => fp.predicate().to_vec(),
            _ => vec![],
        };
        assert_eq!(b"account = 3735928559".to_vec(), predicate);
        let predicate = match &macaroon.caveats()[1] {
            Caveat::FirstParty(fp) => fp.predicate().to_vec(),
            _ => vec![],
        };
        assert_eq!(b"user = alice".to_vec(), predicate);
    }

    #[test]
    fn test_serialize_deserialize() {
        let mut macaroon: Macaroon = Macaroon::create(
            Some("http://example.org/"),
            &MacaroonKey::generate(b"my key"),
            "keyid",
        )
        .unwrap();
        macaroon
            .add_first_party_caveat("account = 3735928559")
            .unwrap();
        macaroon.add_first_party_caveat("user = alice").unwrap();
        macaroon
            .add_third_party_caveat(
                "https://auth.mybank.com",
                &MacaroonKey::generate(b"caveat key"),
                "caveat",
            )
            .unwrap();
        let serialized = macaroon.serialize(super::super::Format::V1).unwrap();
        let deserialized = Macaroon::deserialize(&serialized).unwrap();
        assert_eq!(macaroon, deserialized);
    }

    #[test]
    fn test_max_field_size_roundtrips() {
        // The packet header caps a packet at 0xFFFF bytes, so the largest
        // predicate a V1 `cid` packet can carry is 0xFFFF - 4 - "cid" - 2
        // = 65526 bytes (this matches pymacaroons' maximum). That must
        // round-trip; one byte more must fail loudly at serialize time
        // instead of emitting a corrupt token.
        const MAX_V1_PREDICATE: usize = 0xFFFF - super::HEADER_SIZE - 2 - 3;
        let key = MacaroonKey::generate(b"key");
        let mut macaroon = Macaroon::create(Some("http://example.org/"), &key, "keyid").unwrap();
        let predicate = "x".repeat(MAX_V1_PREDICATE);
        macaroon.add_first_party_caveat(predicate.as_str()).unwrap();
        let serialized = macaroon.serialize(crate::Format::V1).unwrap();
        let deserialized = Macaroon::deserialize(&serialized).unwrap();
        assert_eq!(macaroon, deserialized);

        let mut oversized = Macaroon::create(Some("http://example.org/"), &key, "keyid").unwrap();
        oversized
            .add_first_party_caveat("x".repeat(MAX_V1_PREDICATE + 1).as_str())
            .unwrap();
        let err = oversized.serialize(crate::Format::V1).unwrap_err();
        assert!(matches!(err, crate::MacaroonError::FieldTooLarge { .. }));
        // ...while V2 serializes it fine
        assert!(oversized.serialize(crate::Format::V2).is_ok());
    }

    #[test]
    fn test_packet_after_signature_rejected() {
        let key = MacaroonKey::generate(b"key");
        let mut macaroon = Macaroon::create(Some("http://example.org/"), &key, "keyid").unwrap();
        macaroon.add_first_party_caveat("a = b").unwrap();
        let mut binary = super::serialize_binary(&macaroon).unwrap();
        assert!(super::deserialize(&binary).is_ok());
        binary.extend(super::serialize_as_packet(super::CID, b"dropped = caveat").unwrap());
        let err = super::deserialize(&binary).unwrap_err();
        assert!(err.to_string().contains("after signature"), "{}", err);
    }

    /// Serializes `(tag, value)` pairs back to back into a binary V1 token.
    fn packets(list: &[(&str, &[u8])]) -> Vec<u8> {
        list.iter()
            .flat_map(|&(tag, value)| super::serialize_as_packet(tag, value).unwrap())
            .collect()
    }

    /// Anything out of `location? identifier (cid (vid cl)?)* signature` order
    /// is rejected: duplicates, reorderings, and `vid` / `cl` packets with no
    /// `cid`, which used to be dropped unread.
    #[test]
    fn test_packet_order_enforced() {
        let loc: (&str, &[u8]) = (super::LOCATION, b"http://example.org/");
        let id: (&str, &[u8]) = (super::IDENTIFIER, b"keyid");
        let cid: (&str, &[u8]) = (super::CID, b"caveat");
        let vid: (&str, &[u8]) = (super::VID, b"vid-bytes");
        let cl: (&str, &[u8]) = (super::CL, b"http://auth/");
        let sig: (&str, &[u8]) = (super::SIGNATURE, &[7; 32]);

        let ok = super::deserialize(&packets(&[loc, id, cid, vid, cl, cid, sig])).unwrap();
        assert_eq!(2, ok.caveats().len());

        for (list, expected) in [
            (vec![loc, loc, id, sig], "identifier packet not found"),
            (vec![cid, id, sig], "identifier packet not found"),
            (vec![id, loc, sig], "unexpected location packet"),
            (vec![id, id, sig], "unexpected identifier packet"),
            (vec![id, vid, cl, sig], "vid packet not preceded by a cid"),
            (vec![id, cl, sig], "unexpected cl packet"),
            (vec![id, cid, cl, vid, sig], "unexpected cl packet"),
            (vec![id, cid, vid, sig], "vid packet not followed by a cl"),
            (
                vec![id, cid, vid, cl, vid, cl, sig],
                "vid packet not preceded by a cid",
            ),
            (vec![id, cid, vid, cl, cl, sig], "unexpected cl packet"),
        ] {
            let err = super::deserialize(&packets(&list)).unwrap_err();
            assert!(err.to_string().contains(expected), "{:?}: {}", list, err);
        }
    }

    /// A packet has one encoding: a lowercase hex size, then `key SP value LF`.
    #[test]
    fn test_noncanonical_packets_rejected() {
        let key = MacaroonKey::generate(b"key");
        let macaroon = Macaroon::create(Some("http://example.org/"), &key, "keyid").unwrap();
        let binary = super::serialize_binary(&macaroon).unwrap();
        assert_eq!(macaroon, super::deserialize(&binary).unwrap());
        let (identifier_at, signature_at) = (0x21, 0x21 + 0x15);
        assert_eq!(b"0015", &binary[identifier_at..identifier_at + 4]);
        assert_eq!(b"002f", &binary[signature_at..signature_at + 4]);

        let mutated = |at: usize, byte: u8| {
            let mut token = binary.clone();
            token[at] = byte;
            super::deserialize(&token).unwrap_err().to_string()
        };
        // `from_str_radix` accepted a sign...
        assert!(mutated(identifier_at, b'+').contains("lowercase hex"));
        // ...and uppercase digits
        assert!(mutated(signature_at + 3, b'F').contains("lowercase hex"));
        // the byte ending a packet was dropped whatever it was
        assert!(mutated(signature_at - 1, b'X').contains("newline"));
    }

    #[test]
    fn test_deserialize_bad_data() {
        // these are all expected to fail... but not panic!
        assert!(super::deserialize(b"").is_err());
        assert!(super::deserialize(b"12345").is_err());
        assert!(super::deserialize(b"\0").is_err());
        assert!(super::deserialize(b"NDhJe_A==").is_err());

        // these failed fuzz testing for this deserializer (V1)
        assert!(Macaroon::deserialize(vec![70, 70, 102, 70]).is_err());
        let tok = URL_SAFE.encode([97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 10]);
        assert!(Macaroon::deserialize(tok.as_bytes()).is_err());
        let tok = URL_SAFE.encode([
            48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48,
            48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48,
            48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48,
            48, 48, 48, 48, 48, 48, 48, 44, 125, 59, 64,
        ]);
        assert!(Macaroon::deserialize(tok.as_bytes()).is_err());
        let tok = URL_SAFE.encode([
            48, 48, 49, 48, 49, 48, 52, 48, 48, 48, 48, 48, 48, 48, 48, 32, 126, 10,
        ]);
        assert!(Macaroon::deserialize(tok.as_bytes()).is_err());
    }
}
