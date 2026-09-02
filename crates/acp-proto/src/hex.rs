//! Lowercase hex, the only encoding ACP needs outside base64.
//!
//! Both the topology digest and the HMAC signature go on the wire as lowercase
//! hex, and the panel compares them as strings. This is a few lines, so it lives
//! here rather than as another dependency.

/// Encodes bytes as lowercase hex.
#[must_use]
pub fn encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

/// Decodes lowercase or uppercase hex. Returns `None` on odd length or on any
/// non-hex byte.
#[must_use]
pub fn decode(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.as_chunks::<2>().0 {
        let hi = nibble(pair[0])?;
        let lo = nibble(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

const fn nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn encoding_is_lowercase_and_zero_padded() {
        assert_eq!(super::encode(&[0x00, 0x0f, 0xff, 0xa5]), "000fffa5");
        assert_eq!(super::encode(&[]), "");
    }

    #[test]
    fn decoding_round_trips_and_rejects_malformed_input() {
        assert_eq!(
            super::decode("000fffa5"),
            Some(vec![0x00, 0x0f, 0xff, 0xa5])
        );
        assert_eq!(super::decode("ABCD"), Some(vec![0xab, 0xcd]));
        assert_eq!(super::decode("abc"), None, "odd length");
        assert_eq!(super::decode("zz"), None, "not hex");
    }
}
