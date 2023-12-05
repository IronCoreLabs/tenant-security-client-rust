pub mod attached;

// IronCore EDOC format, quick spec:
//
// -- PRE HEADER (7 bytes) --
// 4                (1 byte)
// IRON             (4 bytes)
// Length of header (2 bytes, BE)
// -- HEADER (proto) --
// -- [optional] DATA --
// The `EncryptedDocumentWithIv` struct is the DATA mentioned in this format

pub(crate) const PRE_HEADER_LEN: usize = 7;
pub(crate) const MAGIC: &[u8; 4] = b"IRON";
pub(crate) const V4: u8 = 4u8;
