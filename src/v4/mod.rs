use crate::icl_header_v4::V4DocumentHeader;

pub mod aes;
pub mod attached;

// IronCore V4 EDOC format, quick spec:
//
// -- PRE HEADER (7 bytes) --
// 4                (1 byte)
// IRON             (4 bytes)
// Length of header (2 bytes, BE)
// -- HEADER (proto) --
// -- [optional] DATA --
// The `IvAndCiphertext` struct is the DATA mentioned in this format

pub(crate) const PRE_HEADER_LEN: usize = 7;
pub(crate) const MAGIC: &[u8; 4] = b"IRON";
pub(crate) const V4: u8 = 4u8;

// Checks that the proto header has a signature, had a valid signature_type, has a signed_payload, and has at least one EDEK
pub fn validate_v4_header(header: &V4DocumentHeader) -> bool {
    header.signature_info.is_some()
        && header.signature_info.signature_type.enum_value().is_ok()
        && header.signed_payload.is_some()
        && !header.signed_payload.edeks.is_empty()
}
