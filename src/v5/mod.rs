use crate::{
    aes::{aes_encrypt, EncryptedDocumentWithIv, EncryptionKey, PlaintextDocument},
    icl_header_v4::V4DocumentHeader,
    key_id_header::{self, KeyIdHeader},
    Error,
};
use bytes::Bytes;
use rand::{CryptoRng, RngCore};

// The V5 data format is defined by 2 data formats. One for the edek and one for encrypted data encrypted with that edek.
// The edek format is a 6 byte key id (see the key_id_header module) followed by a V4DocumentHeader proto.
// The edoc format is the EncryptedPayload below, which is 0 + IRON folowed by the encrypted data (iv, aes encrypted data and tag).

type Result<T> = core::result::Result<T, Error>;
const MAGIC: &[u8; 4] = crate::v4::MAGIC;
pub(crate) const V0: u8 = 0u8;
/// This is 0 + IRON
pub(crate) const DETACHED_HEADER_LEN: usize = 5;

/// These are detached encrypted bytes, which means they have a `0IRON` + IV + CIPHERTEXT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedPayload(pub Bytes);

impl Default for EncryptedPayload {
    fn default() -> EncryptedPayload {
        EncryptedPayload(Bytes::new())
    }
}

impl From<Bytes> for EncryptedPayload {
    fn from(b: Bytes) -> Self {
        EncryptedPayload(b)
    }
}

impl From<Vec<u8>> for EncryptedPayload {
    fn from(v: Vec<u8>) -> Self {
        EncryptedPayload(v.into())
    }
}

impl From<EncryptedPayload> for Bytes {
    fn from(p: EncryptedPayload) -> Self {
        p.0
    }
}

impl EncryptedPayload {
    pub fn to_aes_value_with_attached_iv(self) -> Result<EncryptedDocumentWithIv> {
        let payload_len = self.0.len();
        let mut payload_bytes = self.0;
        if payload_len < DETACHED_HEADER_LEN + crate::aes::IV_LEN {
            Err(Error::EdocTooShort(payload_len))
        } else {
            // Now payload_bytes is the header and iv_and_cipher is the rest.
            let iv_and_cipher = payload_bytes.split_off(DETACHED_HEADER_LEN);
            if payload_bytes != Bytes::from([&[V0], &MAGIC[..]].concat()) {
                Err(Error::NoIronCoreMagic)
            } else {
                Ok(EncryptedDocumentWithIv(iv_and_cipher))
            }
        }
    }

    /// Decrypt a V5 detached document. The document should have the expected header
    pub fn to_plaintext_value(self, key: &EncryptionKey) -> Result<PlaintextDocument> {
        let aes_encrypted_value = self.to_aes_value_with_attached_iv()?;
        crate::aes::aes_decrypt_document_with_attached_iv(key, aes_encrypted_value.as_ref())
    }
}

/// Encrypt a document to be used as a detached document. This means it will have a header of `0IRON` as the first
/// 5 bytes.
pub fn encrypt_detached_document<R: RngCore + CryptoRng>(
    rng: &mut R,
    key: EncryptionKey,
    document: PlaintextDocument,
) -> Result<EncryptedPayload> {
    let (iv, enc_data) = aes_encrypt(key, &document.0, &[], rng)?;
    let payload = EncryptedPayload(
        [&[V0], &MAGIC[..], &iv[..], &enc_data.0[..]]
            .concat()
            .into(),
    );
    Ok(payload)
}

pub fn parse_standard_edek(edek_bytes: Bytes) -> Result<(KeyIdHeader, V4DocumentHeader)> {
    let (key_id_header, proto_bytes) = key_id_header::decode_version_prefixed_value(edek_bytes)?;
    let pb = protobuf::Message::parse_from_bytes(&proto_bytes[..])
        .map_err(|e| Error::HeaderParseErr(e.to_string()))?;
    Ok((key_id_header, pb))
}

pub fn parse_standard_edoc(edoc: Bytes) -> Result<EncryptedDocumentWithIv> {
    EncryptedPayload(edoc).to_aes_value_with_attached_iv()
}

#[cfg(test)]
mod test {
    use super::*;
    use hex_literal::hex;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    #[test]
    fn encrypt_decrypt_detached_document_roundtrips() {
        let mut rng = ChaCha20Rng::seed_from_u64(172u64);
        let key = EncryptionKey(hex!(
            "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
        ));
        let plaintext = PlaintextDocument(vec![100u8, 200u8]);
        let encrypted = encrypt_detached_document(&mut rng, key, plaintext.clone()).unwrap();
        let result = encrypted.to_plaintext_value(&key).unwrap();
        assert_eq!(result, plaintext);
    }

    #[test]
    fn decrypt_fails_no_magic() {
        let key = EncryptionKey(hex!(
            "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
        ));
        let encrypted = EncryptedPayload(
            hex!("fa51152873435062df7e60039d744b248f2e0776d071450f3c879a5895b7")
                .to_vec()
                .into(),
        );

        let result = encrypted.to_plaintext_value(&key).unwrap_err();
        assert_eq!(result, Error::NoIronCoreMagic);
    }

    #[test]
    fn decrypt_fails_too_short() {
        let key = EncryptionKey(hex!(
            "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
        ));
        let encrypted = EncryptedPayload(hex!("0049524f4efa51").to_vec().into());

        let result = encrypted.to_plaintext_value(&key).unwrap_err();
        assert_eq!(result, Error::EdocTooShort(7));
    }
}
