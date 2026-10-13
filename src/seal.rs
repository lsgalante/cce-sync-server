//! Sealing a secret at rest: AES-256-GCM under a key the Worker holds as a
//! secret (`GOOGLE_TOKEN_KEY`, 32 random bytes in base64), so the Google
//! refresh token in SQLite is useless without the Worker's secrets. No
//! Workers types: tested natively. The nonce comes from the caller (the
//! Worker's `crypto.getRandomValues`).

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// The key from its secret's text: base64 of exactly 32 bytes.
pub fn key(secret: &str) -> Result<[u8; 32], String> {
    let bytes = B64.decode(secret.trim()).map_err(|_| "GOOGLE_TOKEN_KEY is not base64".to_string())?;
    bytes.try_into().map_err(|_| "GOOGLE_TOKEN_KEY must be 32 bytes (openssl rand -base64 32)".to_string())
}

/// `base64(nonce ‖ ciphertext)`.
pub fn seal(key: &[u8; 32], nonce: [u8; 12], plain: &str) -> Result<String, String> {
    let cipher = Aes256Gcm::new(key.into());
    let mut out = nonce.to_vec();
    out.extend(cipher.encrypt(Nonce::from_slice(&nonce), plain.as_bytes()).map_err(|_| "sealing failed".to_string())?);
    Ok(B64.encode(out))
}

pub fn open(key: &[u8; 32], sealed: &str) -> Result<String, String> {
    let bytes = B64.decode(sealed).map_err(|_| "sealed value is not base64".to_string())?;
    if bytes.len() < 12 + 16 {
        return Err("sealed value too short".into());
    }
    let cipher = Aes256Gcm::new(key.into());
    let plain = cipher
        .decrypt(Nonce::from_slice(&bytes[..12]), &bytes[12..])
        .map_err(|_| "cannot open the sealed value (another key?)".to_string())?;
    String::from_utf8(plain).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_tamper() {
        let k = key(&B64.encode([7u8; 32])).unwrap();
        let s = seal(&k, [1; 12], "1//refresh-token").unwrap();
        assert_eq!(open(&k, &s).unwrap(), "1//refresh-token");
        assert!(!s.contains("refresh"));
        let other = key(&B64.encode([8u8; 32])).unwrap();
        assert!(open(&other, &s).is_err(), "another key cannot open it");
        let mut bytes = B64.decode(&s).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        assert!(open(&k, &B64.encode(bytes)).is_err(), "tampering is caught");
        assert!(key("short").is_err());
        assert!(key(&B64.encode([0u8; 16])).is_err());
    }
}
