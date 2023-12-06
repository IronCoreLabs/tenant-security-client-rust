use super::{verify_signature, EncryptedPayload};
use crate::{
    aes::{decrypt_attached_document_core, EncryptionKey, PlaintextDocument},
    Error,
};

/// Decrypt a V3 detached document and verifies its signature.
pub fn decrypt_detached_document(
    key: &EncryptionKey,
    payload: EncryptedPayload,
) -> Result<PlaintextDocument, Error> {
    verify_signature(key.0, &payload.v3_document_header);
    decrypt_attached_document_core(key, &payload.iv_and_ciphertext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use itertools::Itertools;

    #[test]
    fn decrypt_good_document() {
        let dek = EncryptionKey((0..32).collect_vec().try_into().unwrap());
        let document = vec![
            3, 73, 82, 79, 78, 0, 42, 10, 28, 20, 31, 98, 61, 23, 74, 221, 61, 102, 44, 153, 142,
            172, 70, 145, 180, 36, 193, 133, 249, 72, 1, 181, 31, 205, 205, 1, 197, 26, 10, 10, 8,
            116, 101, 110, 97, 110, 116, 73, 100, 49, 113, 239, 60, 137, 159, 135, 94, 89, 92, 34,
            19, 231, 165, 112, 184, 171, 237, 133, 20, 97, 193, 60, 0, 85, 139, 184, 144, 44, 184,
            129, 210, 203, 21, 167, 53, 17, 51, 49, 42, 92, 207, 102, 98, 174, 198, 128, 199, 19,
            42, 145, 251, 86, 201, 214, 33, 117, 232, 18, 93,
        ];
        let payload = EncryptedPayload::try_from(document).unwrap();
        let decrypted = decrypt_detached_document(&dek, payload).unwrap();
        assert_eq!(decrypted.0, (0..32).collect_vec());
    }
}
