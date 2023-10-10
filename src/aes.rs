use super::Error;
use crate::{
    icl_header_v4::{self},
    EncryptedDocument, EncryptedPayload, EncryptionKey, PlaintextDocument, MAGIC, V0,
};
use aes_gcm::{aead::Aead, aead::Payload, AeadCore, Aes256Gcm, KeyInit, Nonce};
use bytes::Bytes;
use rand::{CryptoRng, RngCore};

type Result<T> = core::result::Result<T, super::Error>;
const DETATCHED_HEADER_LEN: usize = 5;
const IV_LEN: usize = 12;

pub fn generate_aes_edek<R: CryptoRng + RngCore>(
    rng: &mut R,
    kek: EncryptionKey,
    id: &str,
) -> Result<(
    EncryptionKey,
    icl_header_v4::v4document_header::edek_wrapper::Aes256GcmEncryptedDek,
)> {
    let document_key = {
        let mut buffer = [0u8; 32];
        rng.fill_bytes(&mut buffer);
        buffer
    };
    let (iv, edek) = aes_encrypt(kek, &document_key, &[], rng)?;
    let aes_edek = icl_header_v4::v4document_header::edek_wrapper::Aes256GcmEncryptedDek {
        ciphertext: edek.0.into(),
        iv: Bytes::copy_from_slice(&iv),
        id: id.into(),
        ..Default::default()
    };
    Ok((EncryptionKey(document_key), aes_edek))
}

pub fn decrypt_aes_edek(
    kek: &EncryptionKey,
    aes_edek: &icl_header_v4::v4document_header::edek_wrapper::Aes256GcmEncryptedDek,
) -> Result<EncryptionKey> {
    let iv = aes_edek.iv.as_ref().try_into().map_err(|_| {
        Error::DecryptError("IV from the edek was not the correct length.".to_string())
    })?;
    aes_decrypt(kek, iv, &aes_edek.ciphertext, &[])
        .and_then(|dek_bytes| {
            dek_bytes
                .try_into()
                .map_err(|_| Error::DecryptError("iv was not of the correct size".to_string()))
        })
        .map(|dek_bytes| EncryptionKey(dek_bytes))
}

pub fn decrypt_detatched_document(
    key: &EncryptionKey,
    payload: EncryptedPayload,
) -> Result<PlaintextDocument> {
    let payload_len = payload.0.len();
    if payload_len < DETATCHED_HEADER_LEN + IV_LEN {
        Err(Error::EdocTooShort(payload_len))
    } else {
        let iv = payload
            .0
            .slice(DETATCHED_HEADER_LEN..(DETATCHED_HEADER_LEN + IV_LEN))
            .as_ref()
            .try_into()
            .expect("IV conversion will always have 12 bytes.");
        let ciphertext = payload.0.slice(DETATCHED_HEADER_LEN + IV_LEN..);
        aes_decrypt(key, iv, &ciphertext[..], &[]).map(|v| PlaintextDocument(v))
    }
}

pub fn encrypt_detatched_document<R: RngCore + CryptoRng>(
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
pub(crate) fn aes_encrypt<R: RngCore + CryptoRng>(
    key: EncryptionKey,
    plaintext: &[u8],
    associated_data: &[u8],
    rng: &mut R,
) -> Result<([u8; 12], EncryptedDocument)> {
    let cipher =
        Aes256Gcm::new_from_slice(&key.0).expect("Key length 32 is always valid for Aes256Gcm");
    let iv = Aes256Gcm::generate_nonce(rng);
    let enrcypted_bytes = cipher
        .encrypt(
            &iv,
            Payload {
                msg: plaintext,
                aad: associated_data,
            },
        )
        .map_err(|e| Error::EncryptError(e.to_string()))?;
    Ok((iv.into(), EncryptedDocument(enrcypted_bytes)))
}

pub(crate) fn aes_decrypt(
    key: &EncryptionKey,
    iv: [u8; 12],
    ciphertext: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>> {
    let cipher =
        Aes256Gcm::new_from_slice(&key.0).expect("Key length 32 is always valid for Aes256Gcm");

    cipher
        .decrypt(
            Nonce::from_slice(&iv),
            Payload {
                msg: ciphertext,
                aad: associated_data,
            },
        )
        .map_err(|e| Error::DecryptError(e.to_string()))
}

#[cfg(test)]
mod test {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_probabilistic_roundtrip() {
        let key = EncryptionKey(hex!(
            "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
        ));
        let plaintext = hex!("112233445566778899aabbccddee");
        let (iv, encrypt_result) =
            aes_encrypt(key, &plaintext, &[], &mut rand::thread_rng()).unwrap();
        let decrypt_result = aes_decrypt(&key, iv, &encrypt_result.0, &[]).unwrap();
        assert_eq!(decrypt_result, plaintext);
    }
}
