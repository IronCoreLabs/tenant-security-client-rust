use ring::hmac::{Algorithm, Key as HMACKey};

static HS256: Algorithm = ring::hmac::HMAC_SHA256;
pub struct Signature(pub Vec<u8>);

pub const AES_KEY_LEN: usize = 32;

impl Signature {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}
pub fn sign_hs256(key: [u8; AES_KEY_LEN], payload: &[u8]) -> Signature {
    let hmac_key = HMACKey::new(HS256, &key);
    Signature(ring::hmac::sign(&hmac_key, payload).as_ref().to_vec())
}

pub fn verify_hs256(key: [u8; AES_KEY_LEN], payload: &[u8], sig: &Signature) -> bool {
    let hmac_key = HMACKey::new(HS256, &key);
    ring::hmac::verify(&hmac_key, payload, &sig.0).is_ok()
}

