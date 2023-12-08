// This file contains things related to the V4 AES edek, which is defined in the icl_v4_header.proto.

use crate::{
    aes::{aes_decrypt_core, aes_encrypt, EncryptionKey},
    create_signed_proto, icl_header_v4, Error,
};
use bytes::Bytes;
use rand::{CryptoRng, RngCore};

type Result<T> = core::result::Result<T, crate::Error>;

/// If `maybe_dek` is None, generate a dek, otherwise use the one provided.
/// Encrypt the dek using the kek to make an aes edek. The provided id will be put into the Aes256GcmEncryptedDek.
/// Returns the dek and Aes256GcmEncryptedDek.
pub fn generate_aes_edek<R: CryptoRng + RngCore>(
    rng: &mut R,
    kek: EncryptionKey,
    maybe_dek: Option<EncryptionKey>,
    id: &str,
) -> Result<(
    EncryptionKey,
    icl_header_v4::v4document_header::edek_wrapper::Aes256GcmEncryptedDek,
)> {
    let dek = maybe_dek.unwrap_or_else(|| {
        let mut buffer = [0u8; 32];
        rng.fill_bytes(&mut buffer);
        EncryptionKey(buffer)
    });
    let (iv, edek) = aes_encrypt(kek, &dek.0, &[], rng)?;
    let aes_edek = icl_header_v4::v4document_header::edek_wrapper::Aes256GcmEncryptedDek {
        ciphertext: edek.0.into(),
        iv: Bytes::copy_from_slice(&iv),
        id: id.into(),
        ..Default::default()
    };
    Ok((dek, aes_edek))
}

/// If `maybe_dek` is None, generate a dek, otherwise use the one provided.
/// Encrypt the dek using the kek to make an aes edek. The provided id will be put into the Aes256GcmEdek.
/// The edek will be placed into a V4DocumentHeader and the signature will be computed.
/// The aes dek is the key used to compute the signature.
pub fn generate_aes_edek_and_sign<R: CryptoRng + RngCore>(
    rng: &mut R,
    kek: EncryptionKey,
    maybe_dek: Option<EncryptionKey>,
    id: &str,
) -> Result<(EncryptionKey, icl_header_v4::V4DocumentHeader)> {
    let (aes_dek, aes_edek) = generate_aes_edek(rng, kek, maybe_dek, id)?;
    Ok((
        aes_dek,
        create_signed_proto(
            vec![icl_header_v4::v4document_header::EdekWrapper {
                edek: Some(
                    icl_header_v4::v4document_header::edek_wrapper::Edek::Aes256GcmEdek(aes_edek),
                ),
                ..Default::default()
            }],
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
    aes_decrypt_core(kek, iv, &aes_edek.ciphertext, &[])
        .and_then(|dek_bytes| {
            dek_bytes.try_into().map_err(|_| {
                Error::DecryptError("Decrypted AES DEK was not of the correct size".to_string())
            })
        })
        .map(EncryptionKey)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::verify_signature;
    use hex_literal::hex;
    use protobuf::Message;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    #[test]
    fn generate_aes_edek_decrypts() {
        let mut rng = ChaCha20Rng::seed_from_u64(203u64);
        let kek = EncryptionKey(hex!(
            "aabbccddeefaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
        ));
        let id = "hello";
        let (aes_dek, aes_edek) = generate_aes_edek(&mut rng, kek, None, id).unwrap();
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
        let (aes_dek, v4_document) = generate_aes_edek_and_sign(&mut rng, kek, None, id).unwrap();
        let aes_edek =
            v4_document.signed_payload.0.clone().unwrap().edeks[0].take_aes_256_gcm_edek();
        let decrypted_aes_dek = decrypt_aes_edek(&kek, &aes_edek).unwrap();
        assert_eq!(decrypted_aes_dek, aes_dek);
        let verify_result = verify_signature(decrypted_aes_dek, &v4_document);
        assert!(verify_result)
    }

    #[test]
    fn signed_aes_edek_decrypts() {
        let mut rng = ChaCha20Rng::seed_from_u64(203u64);
        let kek = EncryptionKey(hex!(
            "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
        ));
        let id = "hello";
        let (aes_dek, v4_document) = generate_aes_edek_and_sign(&mut rng, kek, None, id).unwrap();
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
        let verify_result = verify_signature(decrypted_aes_dek, &v4_document);
        // Verify fails because I messed the signature up in the proto_bytes
        assert!(!verify_result)
    }
}
