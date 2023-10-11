use super::Error;
use crate::{
    create_signed_header,
    icl_header_v4::{self, v4document_header::edek_wrapper::Edek},
    EncryptedDocument, EncryptedPayload, EncryptionKey, PlaintextDocument, MAGIC, V0,
};
use aes_gcm::{aead::Aead, aead::Payload, AeadCore, Aes256Gcm, KeyInit, Nonce};
use bytes::Bytes;
use rand::{CryptoRng, RngCore};

type Result<T> = core::result::Result<T, super::Error>;
const DETACHED_HEADER_LEN: usize = 5;
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

/// Generate an aes edek, and encrypt it using the kek. The provided id will be put into the Aes256GcmEdek.
/// The edek will be placed into a V4DocumentHeader and the signature will be computed.
/// The generated aes dek is the key used to compute the signature.
pub fn generate_aes_edek_and_sign<R: CryptoRng + RngCore>(
    rng: &mut R,
    kek: EncryptionKey,
    id: &str,
) -> Result<(EncryptionKey, icl_header_v4::V4DocumentHeader)> {
    let (aes_dek, aes_edek) = generate_aes_edek(rng, kek, id)?;
    Ok((
        aes_dek,
        create_signed_header(
            icl_header_v4::v4document_header::EdekWrapper {
                edek: Some(Edek::Aes256GcmEdek(aes_edek)),
                ..Default::default()
            },
            aes_dek,
        ),
    ))
}

/// Decrypt the aes edek. Does not verify signature of the header or check that the id is appropriate.
/// You must do that as a separate step.
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

/// Decrypt a V4 detached document. The document should have the expected header
pub fn decrypt_detached_document(
    key: &EncryptionKey,
    payload: EncryptedPayload,
) -> Result<PlaintextDocument> {
    let payload_len = payload.0.len();
    if payload_len < DETACHED_HEADER_LEN + IV_LEN {
        Err(Error::EdocTooShort(payload_len))
    } else {
        let (header, iv_and_cipher) = payload.0.split_at(DETACHED_HEADER_LEN);
        if header != [&[V0], &MAGIC[..]].concat() {
            Err(Error::NoIronCoreMagic)
        } else {
            let (iv_slice, ciphertext) = iv_and_cipher.split_at(IV_LEN);
            let iv = iv_slice
                .try_into()
                .expect("IV conversion will always have 12 bytes.");
            aes_decrypt(key, iv, &ciphertext, &[]).map(PlaintextDocument)
        }
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
    use crate::verify_signature;

    use super::*;
    use hex_literal::hex;
    use protobuf::Message;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

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

    #[test]
    fn generate_aes_edek_decrypts() {
        let mut rng = ChaCha20Rng::seed_from_u64(203u64);
        let kek = EncryptionKey(hex!(
            "aabbccddeefaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
        ));
        let id = "hello";
        let (aes_dek, aes_edek) = generate_aes_edek(&mut rng, kek, id).unwrap();
        let result = decrypt_aes_edek(&kek, &aes_edek).unwrap();
        assert_eq!(result, aes_dek);
    }

    #[test]
    fn signed_aes_edek_verifies_and_decrypts() {
        let mut rng = ChaCha20Rng::seed_from_u64(203u64);
        let kek = EncryptionKey(hex!(
            "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
        ));
        let id = "hello";
        let (aes_dek, v4_document) = generate_aes_edek_and_sign(&mut rng, kek, id).unwrap();
        let aes_edek =
            v4_document.signed_payload.0.clone().unwrap().edeks[0].take_aes_256_gcm_edek();
        let decrypted_aes_dek = decrypt_aes_edek(&kek, &aes_edek).unwrap();
        assert_eq!(decrypted_aes_dek, aes_dek);
        let verify_result = verify_signature(decrypted_aes_dek.0, &v4_document);
        assert!(verify_result)
    }

    #[test]
    fn signed_aes_edek_decrypts() {
        let mut rng = ChaCha20Rng::seed_from_u64(203u64);
        let kek = EncryptionKey(hex!(
            "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
        ));
        let id = "hello";
        let (aes_dek, v4_document) = generate_aes_edek_and_sign(&mut rng, kek, id).unwrap();
        let aes_edek = v4_document.signed_payload.0.unwrap().edeks[0].take_aes_256_gcm_edek();
        let result = decrypt_aes_edek(&kek, &aes_edek).unwrap();
        assert_eq!(result, aes_dek);
    }

    #[test]
    fn bad_signature_still_decrypts() {
        let proto_bytes = hex!("0a240a200049fac03b443a5f9d22dae5de3e45d23b2e5705db0843ead925118c59b171d11001124b12491a470a0cde60918359674bd7dc64756512304f4fdd03877ebe65decd71b57ea1cbb070b3fa4c9d29482dbd29a9112165e888e7a8d116be1c4d5e2162a0bb7fe9b03e1a0568656c6c6f");
        let v4_document: icl_header_v4::V4DocumentHeader =
            Message::parse_from_bytes(&proto_bytes).unwrap();
        let kek = EncryptionKey(hex!(
            "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
        ));
        let id = "hello";
        let aes_edek =
            v4_document.signed_payload.0.clone().unwrap().edeks[0].take_aes_256_gcm_edek();
        assert_eq!(aes_edek.id.to_string().as_str(), id);
        let decrypted_aes_dek = decrypt_aes_edek(&kek, &aes_edek).unwrap();
        let verify_result = verify_signature(decrypted_aes_dek.0, &v4_document);
        // Verify fails because I messed the signature up in the proto_bytes
        assert!(!verify_result)
    }

    #[test]
    fn encrypt_decrypt_detached_document_roundtrips() {
        let mut rng = ChaCha20Rng::seed_from_u64(172u64);
        let key = EncryptionKey(hex!(
            "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
        ));
        let plaintext = PlaintextDocument(vec![100u8, 200u8]);
        let encrypted = encrypt_detached_document(&mut rng, key, plaintext.clone()).unwrap();
        let result = decrypt_detached_document(&key, encrypted).unwrap();
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

        let result = decrypt_detached_document(&key, encrypted).unwrap_err();
        assert_eq!(result, Error::NoIronCoreMagic);
    }

    #[test]
    fn decrypt_fails_too_short() {
        let key = EncryptionKey(hex!(
            "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
        ));
        let encrypted = EncryptedPayload(hex!("0049524f4efa51").to_vec().into());

        let result = decrypt_detached_document(&key, encrypted).unwrap_err();
        assert_eq!(result, Error::EdocTooShort(7));
    }
}
