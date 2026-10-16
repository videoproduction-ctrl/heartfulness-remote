//! base64url helpers. The protocol encodes every binary value as base64url
//! *without* padding (docs/PROTOCOL.md §2). Decoding tolerates padding so a
//! padded value from a sloppy caller is not misread, but output never has it.

use base64::alphabet::URL_SAFE;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig};
use base64::engine::DecodePaddingMode;
use base64::Engine as _;

use crate::Error;

const ENGINE: GeneralPurpose = GeneralPurpose::new(
    &URL_SAFE,
    GeneralPurposeConfig::new()
        .with_encode_padding(false)
        .with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

/// Encode as base64url without padding.
pub fn encode(bytes: &[u8]) -> String {
    ENGINE.encode(bytes)
}

/// Decode base64url (padding optional). `what` names the argument in errors.
pub fn decode(s: &str, what: &str) -> Result<Vec<u8>, Error> {
    ENGINE
        .decode(s.as_bytes())
        .map_err(|_| Error::InvalidInput(format!("{what} is not valid base64url")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_no_padding() {
        let data = [0xfbu8, 0xff, 0x00, 0x01];
        let s = encode(&data);
        assert_eq!(s, "-_8AAQ");
        assert!(!s.contains('='));
        assert_eq!(decode(&s, "x").unwrap(), data);
    }

    #[test]
    fn accepts_padding_rejects_std_alphabet() {
        assert_eq!(decode("-_8AAQ==", "x").unwrap(), [0xfb, 0xff, 0x00, 0x01]);
        assert!(decode("+/8AAQ", "x").is_err());
        assert!(decode("not base64!", "x").is_err());
    }
}
