mod signing;

use self::icl_header_v4::V4DocumentHeader;
use bytes::{Buf, Bytes};
use icl_header_v4::v4document_header::{
    signature_information::SignatureType, SignatureInformation, SignedPayload,
};
use protobuf::Message;
use signing::AES_KEY_LEN;
use std::fmt::{Display, Formatter, Result as DisplayResult};
use thiserror::Error;

include!(concat!(env!("OUT_DIR"), "/mod.rs"));

#[derive(Error, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Error {
    /// EDOCs have a minimum size (at least the size of the pre-header)
    EdocTooShort(usize),
    /// Header could not be parsed as proto
    HeaderParseErr(String),
    /// EDOC version is not supported
    InvalidVersion(u8),
    /// 'IRON' as bytes
    NoIronCoreMagic,
    /// specified length of header is larger than the remaining data (proto header + payload)
    SpecifiedLengthTooLong(u32),
    /// Error occurred when serializing the header as proto
    ProtoSerializationErr(String),
    /// Serialized header is longer than allowed. Value is actual length in bytes.
    HeaderLengthOverflow(u64),
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> DisplayResult {
        match self {
            Error::EdocTooShort(x) => write!(f, "EdocTooShort({x})"),
            Error::HeaderParseErr(x) => write!(f, "HeaderParseErr({x})"),
            Error::InvalidVersion(x) => write!(f, "InvalidVersion({x})"),
            Error::NoIronCoreMagic => write!(f, "NoIronCoreMagic"),
            Error::SpecifiedLengthTooLong(x) => write!(f, "SpecifiedLengthTooLong({x})"),
            Error::ProtoSerializationErr(x) => write!(f, "ProtoSerializationErr({x})"),
            Error::HeaderLengthOverflow(x) => write!(f, "HeaderLengthOverflow({x})"),
        }
    }
}

const PRE_HEADER_LEN: usize = 7;
const MAGIC: &[u8; 4] = b"IRON";
const V4: u8 = 4u8;

// IronCore EDOC format, quick spec:
//
// -- PRE HEADER (7 bytes) --
// 4                (1 byte)
// IRON             (4 bytes)
// Length of header (2 bytes, BE)
// -- HEADER (proto) --
// -- [optional] DATA --

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedPayload(pub Bytes);

impl Default for EncryptedPayload {
    fn default() -> EncryptedPayload {
        EncryptedPayload([].as_ref().into())
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

fn get_v4_header_and_payload(mut b: Bytes) -> Result<(Bytes, EncryptedPayload), Error> {
    let initial_len = b.len();
    if initial_len >= PRE_HEADER_LEN {
        let first_byte = b.get_u8();
        if first_byte == V4 {
            //Check to see if the next 4 bytes are the IRON ascii chars
            let maybe_magic = b.split_to(MAGIC.len());
            Some(maybe_magic)
                .filter(|bytes| *bytes == MAGIC[..])
                .ok_or(Error::NoIronCoreMagic)?;
            //The following 2 bytes should be a u16 (big endian). This is the size of the PB header
            let header_size = b.get_u16().into();
            if b.len() >= header_size {
                //Break off the bytes after `header_size` and leave the header in `b`.
                let rest = b.split_off(header_size);
                Ok((b, EncryptedPayload(rest)))
            } else {
                Err(Error::SpecifiedLengthTooLong(header_size as u32))
            }
        } else {
            Err(Error::InvalidVersion(first_byte))
        }
    } else {
        Err(Error::EdocTooShort(initial_len))
    }
}

pub fn decode_edoc(b: Bytes) -> Result<(V4DocumentHeader, EncryptedPayload), Error> {
    let (header_bytes, attached_document) = get_v4_header_and_payload(b)?;

    let pb = protobuf::Message::parse_from_bytes(&header_bytes[..])
        .map_err(|e| Error::HeaderParseErr(e.to_string()))?;
    Ok((pb, attached_document))
}

/// Construct an IronCore EDOC from the constituent parts.
pub fn encode_edoc(header: V4DocumentHeader, payload: EncryptedPayload) -> Result<Bytes, Error> {
    let encoded_header: Vec<u8> = header
        .write_to_bytes()
        .map_err(|e| Error::ProtoSerializationErr(e.to_string()))?;
    if encoded_header.len() > u16::MAX as usize {
        Err(Error::HeaderLengthOverflow(encoded_header.len() as u64))
    } else {
        let len = encoded_header.len() as u16;

        let result = [
            &[V4],
            &MAGIC[..],
            &len.to_be_bytes(),
            &encoded_header,
            &payload.0,
        ]
        .concat();
        Ok(result.into())
    }
}

pub fn sign_header(key: [u8; AES_KEY_LEN], header_payload: &SignedPayload) -> SignatureInformation {
    //This unwrap can't actually ever happen because they create the coded stream with exactly the computed size before
    //serializing.
    let bytes = header_payload
        .write_to_bytes()
        .expect("Writing proto to bytes failed.");
    let signature = signing::sign_hs256(key, &bytes);

    SignatureInformation {
        signature: signature.0.to_vec().into(),
        signature_type: SignatureType::HS256.into(),
        ..Default::default()
    }
}

pub fn verify_signature(key: [u8; AES_KEY_LEN], header: &V4DocumentHeader) -> bool {
    match header.signature_info.signature_type.enum_value() {
        Ok(SignatureType::NONE) => true,
        Ok(SignatureType::HS256) => {
            if let Ok(signature_bytes) = header.signature_info.signature.to_vec().try_into() {
                signing::verify_hs256(
                    key,
                    //This unwrap can't actually ever happen because they create the coded stream with exactly the computed size before
                    //serializing.
                    &header
                        .signed_payload
                        .write_to_bytes()
                        .expect("Writing proto to bytes failed."),
                    &signing::Signature(signature_bytes),
                )
            } else {
                false
            }
        }
        _ => false,
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::icl_header_v4::v4document_header::{
        edek_wrapper::{Aes256GcmEncryptedDek, Edek},
        EdekWrapper,
    };

    #[test]
    fn edoc_encode_decode_roundtrip() -> Result<(), Error> {
        let header = V4DocumentHeader::default();
        let payload = EncryptedPayload([42u8; 10].as_ref().into());

        // with payload
        let edoc = encode_edoc(header.clone(), payload.clone())?;
        let (decoded_header, decoded_payload) = decode_edoc(edoc)?;

        assert_eq!(&decoded_header, &header);
        assert_eq!(decoded_payload, payload);

        // No payload
        let edoc2 = encode_edoc(header.clone(), EncryptedPayload::default())?;
        let (decoded_header2, decoded_payload2) = decode_edoc(edoc2)?;
        assert!(decoded_payload2.0.is_empty());
        assert_eq!(&decoded_header2, &header);
        Ok(())
    }

    #[test]
    fn edoc_encode_fail_headers_too_long() {
        let aes_edek = Aes256GcmEncryptedDek {
            //V4DocumentHeader_EdekWrapper_Aes256GcmEncryptedDek {
            ciphertext: [42u8; u16::MAX as usize + 1].as_ref().into(),
            ..Default::default()
        };

        let edek_wrapper = EdekWrapper {
            edek: Some(Edek::Aes256GcmEdek(aes_edek)),
            ..Default::default()
        };

        let signed_payload = SignedPayload {
            edeks: vec![edek_wrapper],
            ..Default::default()
        };

        let header = V4DocumentHeader {
            signed_payload: Some(signed_payload).into(),
            ..Default::default()
        };

        let result = encode_edoc(header, EncryptedPayload::default());
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            Error::HeaderLengthOverflow(_)
        ));
    }

    #[test]
    fn decode_bad_version() -> Result<(), Error> {
        let header = V4DocumentHeader::default();
        let payload = EncryptedPayload([42u8; 10].as_ref().into());

        let mut edoc = encode_edoc(header, payload)?.to_vec();
        edoc[0] = 3;
        let result = decode_edoc(edoc.into());
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::InvalidVersion(3)));
        Ok(())
    }

    #[test]
    fn decode_too_short() {
        let result = decode_edoc(vec![7u8].into());
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::EdocTooShort(1)));
    }

    #[test]
    fn decode_bad_magic() -> Result<(), Error> {
        let header = V4DocumentHeader::default();

        let mut edoc = encode_edoc(header, EncryptedPayload::default())?.to_vec();
        // bytes [1] to [4] should be IRON
        edoc[4] = b"M"[0];
        let result = decode_edoc(edoc.into());
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::NoIronCoreMagic));
        Ok(())
    }

    #[test]
    fn decode_bad_header_len() -> Result<(), Error> {
        let header = V4DocumentHeader::default();

        let mut edoc = encode_edoc(header, EncryptedPayload::default())?.to_vec();
        // bytes [5] and [6] are a u16 saying how long the header is.
        // the data following must be at least as long as the header len
        let len = 1u16.to_be_bytes();
        assert_eq!(len.len(), 2);

        edoc[5] = len[0];
        edoc[6] = len[1];
        let result = decode_edoc(edoc.into());
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            Error::SpecifiedLengthTooLong(_)
        ));
        Ok(())
    }

    #[test]
    fn sign_verify_roundtrip() {
        let dek: [u8; 32] = [100u8; AES_KEY_LEN];
        let aes_edek = Aes256GcmEncryptedDek {
            ciphertext: [42u8; 1024].as_ref().into(),
            ..Default::default()
        };

        let edek_wrapper = EdekWrapper {
            edek: Some(Edek::Aes256GcmEdek(aes_edek)),
            ..Default::default()
        };

        let signed_payload = SignedPayload {
            edeks: vec![edek_wrapper],
            ..Default::default()
        };

        let mut header = V4DocumentHeader {
            signed_payload: Some(signed_payload).into(),
            ..Default::default()
        };

        let sign_result = sign_header(dek, &header.signed_payload);

        header.signature_info = Some(sign_result).into();
        assert!(verify_signature(dek, &header));
    }

    #[test]
    fn verify_known_good_sig_in_v4_header() {
        let dek: [u8; 32] = [100u8; AES_KEY_LEN];
        let bytes = hex_literal::hex!("0a240a2082e7f2abc390635636f59ea51f7736846d9b1e799f4e9b63733679a417a2c5cf10011289081286081a83081280082a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a");
        let header = Message::parse_from_bytes(&bytes).unwrap();
        assert!(verify_signature(dek, &header))
    }
}
