use bytes::{Buf, Bytes};
use protobuf::Message;

use crate::{aes::IvAndCiphertext, icl_header_v4::V4DocumentHeader, Error};

use super::key_id_header::{self, KeyIdHeader};

type Result<A> = std::result::Result<A, Error>;

#[derive(Debug, PartialEq)]
pub struct AttachedDocument {
    pub key_id_header: KeyIdHeader,
    pub edek: V4DocumentHeader,
    pub edoc: IvAndCiphertext,
}

/// Construct an IronCore attached EDOC from the constituent parts.
pub fn encode_attached_edoc(
    AttachedDocument {
        key_id_header,
        edek,
        edoc,
    }: &AttachedDocument,
) -> Result<Bytes> {
    let key_id_header_bytes = key_id_header.write_to_bytes();
    let encoded_edek = edek.write_to_bytes().expect("Writing to bytes is safe");
    if encoded_edek.len() > u16::MAX as usize {
        Err(Error::HeaderLengthOverflow(encoded_edek.len() as u64))
    } else {
        let len = encoded_edek.len() as u16;

        let result = [
            key_id_header_bytes.as_ref(),
            &len.to_be_bytes(),
            &encoded_edek,
            &edoc.0, // Note that the edoc is written without a header since it's an attached document.
        ]
        .concat();
        Ok(result.into())
    }
}

/// Breaks apart an attached edoc into its parts.
pub fn decode_attached_edoc(b: Bytes) -> Result<AttachedDocument> {
    let (key_id_header, mut attached_document_with_header) =
        key_id_header::decode_version_prefixed_value(b)?;
    if attached_document_with_header.len() > 2 {
        let len = attached_document_with_header.get_u16();
        if attached_document_with_header.len() > len as usize {
            let header_bytes = attached_document_with_header.split_to(len as usize);
            let edek = protobuf::Message::parse_from_bytes(&header_bytes[..])
                .map_err(|e| Error::HeaderParseErr(e.to_string()))?;
            Ok(AttachedDocument {
                key_id_header,
                edek,
                edoc: IvAndCiphertext(attached_document_with_header),
            })
        } else {
            Err(Error::HeaderParseErr("Edek length too long.".to_string()))
        }
    } else {
        Err(Error::HeaderParseErr("Header is too short.".to_string()))
    }
}

#[cfg(test)]
mod test {
    use crate::{
        aes::IvAndCiphertext,
        icl_header_v4::{
            v4document_header::{
                edek_wrapper::{Aes256GcmEncryptedDek, Edek},
                EdekWrapper, SignedPayload,
            },
            V4DocumentHeader,
        },
        v5::key_id_header::{EdekType, KeyId, KeyIdHeader, PayloadType},
        Error,
    };

    use super::{decode_attached_edoc, encode_attached_edoc, AttachedDocument};

    #[test]
    fn test_roundtrip() {
        let key_id_header = KeyIdHeader::new(
            EdekType::SaasShield,
            PayloadType::StandardEdek,
            KeyId(u32::MAX),
        );

        let edek_wrapper = EdekWrapper {
            edek: Some(Edek::Aes256GcmEdek(Aes256GcmEncryptedDek {
                ciphertext: [42u8; 255].as_ref().into(),
                ..Default::default()
            })),
            ..Default::default()
        };

        let edek = V4DocumentHeader {
            signed_payload: Some(SignedPayload {
                edeks: vec![edek_wrapper],
                ..Default::default()
            })
            .into(),
            ..Default::default()
        };

        let edoc = IvAndCiphertext(vec![100, 200, 0].into());
        let expected_result = AttachedDocument {
            key_id_header,
            edek,
            edoc,
        };
        let encoded = encode_attached_edoc(&expected_result).unwrap();
        let result = decode_attached_edoc(encoded).unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn test_len_too_long() {
        // The `0,255` after the `0` is the u16 representing length. It is too large.
        let encoded = vec![
            255u8, 255, 255, 255, 2, 0, 0, 255, 18, 7, 18, 5, 26, 3, 18, 1, 42, 100, 200,
        ]
        .into();
        let result = decode_attached_edoc(encoded).unwrap_err();
        assert_eq!(
            result,
            Error::HeaderParseErr("Edek length too long.".to_string())
        );
    }

    #[test]
    fn test_header_too_short() {
        // This value is just a key_id header with 1 0 after.
        let encoded = vec![255u8, 255, 255, 255, 2, 0, 0].into();
        let result = decode_attached_edoc(encoded).unwrap_err();
        assert_eq!(
            result,
            Error::HeaderParseErr("Header is too short.".to_string())
        );
    }
}
