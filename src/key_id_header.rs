use bytes::Bytes;
use itertools::Itertools;
use protobuf::Message;

use crate::{vector_encryption_metadata::VectorEncryptionMetadata, Error};

// This file is for functions which are working with our key id header value.
// This value has the following structure:
// 4 Byte id. This value is a u32 encoded in big endian format.
// 1 Byte where the first 4 bits are used for which type of edek the id points to (Standalone, Saas Shield, DCP).
//   The next 4 bits are to denote which type of data follows it (vector metadata, IronCore Edoc, deterministic ciphertext)

const SAAS_SHIELD_EDEK_TYPE_NUM: u8 = 0u8;
const STANDALONE_EDEK_TYPE_NUM: u8 = 128u8;

type Result<A> = std::result::Result<A, super::Error>;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyId(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EdekType {
    SaasShield,
    Standalone,
}

impl EdekType {
    pub(crate) fn to_numeric_value(self) -> u8 {
        match self {
            EdekType::SaasShield => SAAS_SHIELD_EDEK_TYPE_NUM,
            EdekType::Standalone => STANDALONE_EDEK_TYPE_NUM,
        }
    }

    pub(crate) fn from_numeric_value(candidate: &u8) -> Result<EdekType> {
        if candidate == &SAAS_SHIELD_EDEK_TYPE_NUM {
            Ok(EdekType::SaasShield)
        } else if candidate == &STANDALONE_EDEK_TYPE_NUM {
            Ok(EdekType::Standalone)
        } else {
            Err(Error::EdekTypeError(
                "Byte {candidate} isn't a valid edek type.".to_string(),
            ))
        }
    }
    pub fn create_header(&self, key_id: KeyId) -> Bytes {
        let iter = u32::to_be_bytes(key_id.0)
            .into_iter()
            .chain([self.to_numeric_value(), 0u8]);
        Bytes::from_iter(iter)
    }

    pub(crate) fn parse_from_bytes(b: Bytes) -> Result<EdekType> {
        b.first()
            .ok_or_else(|| Error::EdekTypeError("EdekType couldn't be determined.".to_string()))
            .and_then(Self::from_numeric_value)
    }
}

// TODO: Payload type not implemented here yet.
pub fn create_vector_metadata(
    edek_type: EdekType,
    key_id: KeyId,
    iv: Bytes,
    auth_hash: Bytes,
) -> (Bytes, VectorEncryptionMetadata) {
    let key_id_header = edek_type.create_header(key_id);
    let vector_encryption_metadata = VectorEncryptionMetadata {
        iv,
        auth_hash,
        ..Default::default()
    };
    (key_id_header, vector_encryption_metadata)
}

/// Form the bytes that represent the vector metadata to the outside world.
/// This is the protobuf with the key_id_header put onto the front.
pub fn encode_vector_metadata(
    key_id_header: Bytes,
    vector_metadata: VectorEncryptionMetadata,
) -> Bytes {
    key_id_header
        .into_iter()
        .chain(
            vector_metadata
                .write_to_bytes()
                .expect("Writing to in memory bytes failed"),
        )
        .collect_vec()
        .into()
}

/// Decode a value which has the key_id_header put on the front by breaking it up.
/// This returns the key id, edek type and the remaining bytes.
pub fn decode_version_prefixed_value(mut value: Bytes) -> Result<(KeyId, EdekType, Bytes)> {
    let value_len = value.len();
    if value_len >= 6 {
        let rest = value.split_off(6);
        let padding_bytes = value.split_off(4);
        let id = {
            let id_byte_sized: [u8; 4] = value.to_vec().try_into().unwrap();
            KeyId(u32::from_be_bytes(id_byte_sized))
        };
        // What's left in header is 2 bytes for the padding
        let edek_type = EdekType::parse_from_bytes(padding_bytes)?;
        Ok((id, edek_type, rest))
    } else {
        Err(Error::KeyIdHeaderTooShort(value_len))
    }
}

pub fn get_prefix_bytes_for_search(key_id: KeyId, edek_type: EdekType) -> Bytes {
    edek_type.create_header(key_id)
}

#[cfg(test)]
mod test {

    use super::*;
    #[test]
    fn test_create_produces_saas_shield() {
        let iv_bytes: Bytes = (1..12).collect_vec().into();
        let auth_hash_bytes: Bytes = (1..16).collect_vec().into();
        let (header, result) = create_vector_metadata(
            EdekType::SaasShield,
            KeyId(72000),
            iv_bytes.clone(),
            auth_hash_bytes.clone(),
        );
        assert_eq!(
            header.to_vec(),
            vec![0, 1, 25, 64, SAAS_SHIELD_EDEK_TYPE_NUM, 0]
        );
        assert_eq!(result.iv, iv_bytes);
        assert_eq!(result.auth_hash, auth_hash_bytes);
    }

    #[test]
    fn test_create_produces_standalone() {
        let iv_bytes: Bytes = (1..12).collect_vec().into();
        let auth_hash_bytes: Bytes = (1..16).collect_vec().into();
        let (header, result) = create_vector_metadata(
            EdekType::Standalone,
            KeyId(72000),
            iv_bytes.clone(),
            auth_hash_bytes.clone(),
        );
        assert_eq!(
            header.to_vec(),
            vec![0, 1, 25, 64, STANDALONE_EDEK_TYPE_NUM, 0]
        );
        assert_eq!(result.iv, iv_bytes);
        assert_eq!(result.auth_hash, auth_hash_bytes);
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let iv_bytes: Bytes = (1..12).collect_vec().into();
        let auth_hash_bytes: Bytes = (1..16).collect_vec().into();
        let key_id = KeyId(72000);
        let (header, result) = create_vector_metadata(
            EdekType::Standalone,
            key_id,
            iv_bytes.clone(),
            auth_hash_bytes.clone(),
        );

        let encode_result = encode_vector_metadata(header, result.clone());
        let (final_key_id, final_edek_type, final_vector_bytes) =
            decode_version_prefixed_value(encode_result).unwrap();
        assert_eq!(final_key_id, key_id);
        assert_eq!(final_edek_type, EdekType::Standalone);
        assert_eq!(final_vector_bytes, result.write_to_bytes().unwrap());
    }
}
