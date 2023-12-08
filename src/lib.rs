pub mod aes;
pub mod key_id_header;
mod signing;
pub mod v3;
pub mod v4;
pub mod v5;

use self::icl_header_v4::V4DocumentHeader;
use icl_header_v4::v4document_header::{
    signature_information::SignatureType, SignatureInformation, SignedPayload,
};
use protobuf::Message;
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
    /// Encryption of the edoc failed.
    EncryptError(String),
    /// Decryption of the edoc failed.
    DecryptError(String),
    // The next errors have to do with the key_id_header
    /// EdekType was not recognized
    EdekTypeError(String),
    /// PayloadType was not recognized
    PayloadTypeError(String),
    /// key_id_header to short
    KeyIdHeaderTooShort(usize),
    /// key_id_header malformed
    KeyIdHeaderMalformed(String),
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
            Error::EncryptError(x) => write!(f, "EncryptError({x})"),
            Error::DecryptError(x) => write!(f, "DecryptError({x})"),
            Error::KeyIdHeaderTooShort(x) => write!(f, "KeyIdHeaderTooShort({x})"),
            Error::EdekTypeError(x) => write!(f, "EdekTypeError({x})"),
            Error::PayloadTypeError(x) => write!(f, "PayloadTypeError({x})"),
            Error::KeyIdHeaderMalformed(x) => write!(f, "KeyIdHeaderMalformed({x})"),
        }
    }
}

/// Creates a signed proto wrapper with a single edek wrapper in it using the signing key to do the signing.
pub fn create_signed_proto(
    edek_wrappers: Vec<icl_header_v4::v4document_header::EdekWrapper>,
    signing_key: aes::EncryptionKey,
) -> V4DocumentHeader {
    let signed_payload = icl_header_v4::v4document_header::SignedPayload {
        edeks: edek_wrappers,
        ..Default::default()
    };
    let signature_info = sign_header(signing_key, &signed_payload);
    icl_header_v4::V4DocumentHeader {
        signed_payload: Some(signed_payload).into(),
        signature_info: Some(signature_info).into(),
        ..Default::default()
    }
}

/// Sign the payload using the key.
pub fn sign_header(
    key: aes::EncryptionKey,
    header_payload: &SignedPayload,
) -> SignatureInformation {
    //This unwrap can't actually ever happen because they create the coded stream with exactly the computed size before
    //serializing.
    let bytes = header_payload
        .write_to_bytes()
        .expect("Writing proto to bytes failed.");
    let signature = signing::sign_hs256(key.0, &bytes);

    SignatureInformation {
        signature: signature.0.to_vec().into(),
        signature_type: SignatureType::HS256.into(),
        ..Default::default()
    }
}

/// Verify the signature inside the
pub fn verify_signature(key: aes::EncryptionKey, header: &V4DocumentHeader) -> bool {
    match header.signature_info.signature_type.enum_value() {
        Ok(SignatureType::NONE) => true,
        Ok(SignatureType::HS256) => {
            if let Ok(signature_bytes) = header.signature_info.signature.to_vec().try_into() {
                signing::verify_hs256(
                    key.0,
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
    use crate::signing::AES_KEY_LEN;
    use crate::{
        aes::EncryptionKey,
        icl_header_v4::v4document_header::{
            edek_wrapper::{Aes256GcmEncryptedDek, Edek},
            EdekWrapper,
        },
    };

    #[test]
    fn sign_verify_roundtrip() {
        let dek = EncryptionKey([100u8; AES_KEY_LEN]);
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
        let dek = EncryptionKey([100u8; AES_KEY_LEN]);
        let bytes = hex_literal::hex!("0a240a2082e7f2abc390635636f59ea51f7736846d9b1e799f4e9b63733679a417a2c5cf10011289081286081a83081280082a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a");
        let header = Message::parse_from_bytes(&bytes).unwrap();
        assert!(verify_signature(dek, &header))
    }
}
