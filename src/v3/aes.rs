use super::{verify_signature, IV_LEN};
use crate::{
    aes::{decrypt_attached_document_core, EncryptionKey, PlaintextDocument},
    EncryptedPayload, Error, MAGIC,
};
use protobuf::Message;

// [3, b"IRON", <2 bytes of header len>]
const DETACHED_HEADER_LEN: usize = 7;

const V3: u8 = 3u8;

/// Decrypt a V3 detached document and verifies its signature.
pub fn decrypt_detached_document(
    key: &EncryptionKey,
    payload: EncryptedPayload,
) -> Result<PlaintextDocument, Error> {
    let payload_len = payload.0.len();
    if payload_len < DETACHED_HEADER_LEN + IV_LEN {
        Err(Error::EdocTooShort(payload_len))?
    };
    let (magic_header, header_and_len_and_cipher) = payload.0.split_at(5);
    if magic_header != [&[V3], &MAGIC[..]].concat() {
        Err(Error::NoIronCoreMagic)?
    };
    let (header_len_bytes, header_and_cipher) = header_and_len_and_cipher.split_at(2);
    // unwrap is safe because we split off 2 bytes
    let header_len = u16::from_be_bytes(header_len_bytes.try_into().unwrap()) as usize;
    if header_and_cipher.len() < header_len {
        Err(Error::HeaderParseErr(format!(
            "Proto header length specified: {}, bytes remaining: {}",
            header_len,
            header_and_cipher.len()
        )))?
    };
    let (header, iv_and_cipher) = header_and_cipher.split_at(header_len);
    let v3_document_header = Message::parse_from_bytes(header).map_err(|_| {
        Error::HeaderParseErr("Unable to parse header as V3DocumentHeader".to_string())
    })?;
    verify_signature(key.0, &v3_document_header);
    decrypt_attached_document_core(key, iv_and_cipher)
}

#[cfg(test)]
mod tests {
    use super::*;
    use itertools::Itertools;

    #[test]
    fn decrypt_too_short() {
        let dek = EncryptionKey([1; 32]);
        let document = &[3, 73, 82, 79, 78, 0][..];
        let err = decrypt_detached_document(&dek, EncryptedPayload(document.into()));
        assert!(matches!(err, Err(Error::EdocTooShort(_))))
    }

    #[test]
    fn decrypt_invalid_header_len() {
        let dek = EncryptionKey([1; 32]);
        let document = &[
            3, 73, 82, 79, 78, 0, 100, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        ][..];
        let err = decrypt_detached_document(&dek, EncryptedPayload(document.into()));
        assert!(matches!(err, Err(Error::HeaderParseErr(_))))
    }

    #[test]
    fn decrypt_no_magic() {
        let dek = EncryptionKey([1; 32]);
        let document = &[1, 73, 82, 79, 78, 0, 12, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1][..];
        let err = decrypt_detached_document(&dek, EncryptedPayload(document.into()));
        assert!(matches!(err, Err(Error::NoIronCoreMagic)))
    }

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
        let decrypted = decrypt_detached_document(&dek, EncryptedPayload(document.into())).unwrap();
        assert_eq!(decrypted.0, (0..32).collect_vec());
    }
}
