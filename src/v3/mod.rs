use crate::{aes::aes_encrypt_with_iv, icl_header_v3::V3DocumentHeader, signing::AES_KEY_LEN};
pub use aes::decrypt_detached_document;
use bytes::Bytes;
use protobuf::Message;

mod aes;

const IV_LEN: usize = 12;
const GCM_TAG_LEN: usize = 16;

struct V3Signature {
    iv: [u8; IV_LEN],
    gcm_tag: [u8; GCM_TAG_LEN],
}

fn decompose_signature(sig: &Bytes) -> Option<V3Signature> {
    if sig.len() < IV_LEN + GCM_TAG_LEN {
        None
    } else {
        let (iv, _) = sig.split_at(IV_LEN);
        let (_, gcm_tag) = sig.split_at(sig.len() - GCM_TAG_LEN);
        Some(V3Signature {
            iv: iv.try_into().unwrap(),           // Length was validated up-front
            gcm_tag: gcm_tag.try_into().unwrap(), // Length was validated up-front
        })
    }
}

pub fn verify_signature(key: [u8; AES_KEY_LEN], v3_header: &V3DocumentHeader) -> bool {
    // If we have no header or authTag, that means this document was encrypted before the header was added, which would only happen if the
    // document was encrypted with the Java SDK. In that case, we'll just ignore the verification and try to decrypt, which might still work.
    if v3_header.header.is_none() || !v3_header.has_saas_shield() || v3_header.sig.is_empty() {
        true
    } else {
        let maybe_sig = decompose_signature(&v3_header.sig);
        match maybe_sig {
            Some(sig) => aes_encrypt_with_iv(
                crate::aes::EncryptionKey(key),
                &v3_header
                    .saas_shield()
                    .write_to_bytes()
                    .expect("Writing proto to bytes failed."),
                sig.iv,
                &[],
            )
            .map(|(_, new_sig)| {
                let new_sig_length = new_sig.0.len();
                let (_, new_gcm_tag) = new_sig.0.split_at(new_sig_length - GCM_TAG_LEN);
                new_gcm_tag == sig.gcm_tag
            })
            .unwrap_or(false),
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;
    use itertools::Itertools;

    #[test]
    fn verify_known_good_sig_in_v3_header() {
        // dek and proto_bytes copied from TSC-java test
        let dek: [u8; 32] = (0..32).into_iter().collect_vec().try_into().unwrap();
        let proto_bytes = vec![
            10, 28, 49, 113, -17, 60, -119, -97, -121, 94, 89, 92, 34, 19, -54, -49, -110, -121,
            -57, -116, -15, -106, 69, -116, -42, -112, 84, 73, -128, -57, 26, 10, 10, 8, 116, 101,
            110, 97, 110, 116, 73, 100,
        ]
        .into_iter()
        .map(|x| x as u8)
        .collect_vec();
        let header = Message::parse_from_bytes(&proto_bytes).unwrap();
        assert!(verify_signature(dek, &header))
    }

    #[test]
    fn verify_known_bad_sig_in_v3_header() {
        // {
        //   "sig": [1, 2, 3],
        //   "saas_shield": {
        //     "tenant_id": "tenantId"
        //   }
        // }
        let proto_bytes = hex!("0a030102031a0a0a0874656e616e744964");
        let dek: [u8; 32] = (0..32).into_iter().collect_vec().try_into().unwrap();
        let header = Message::parse_from_bytes(&proto_bytes).unwrap();
        assert!(!verify_signature(dek, &header));
    }

    #[test]
    fn verify_empty_v3_header() {
        let dek: [u8; 32] = (0..32).into_iter().collect_vec().try_into().unwrap();
        let empty_header = V3DocumentHeader::new();
        assert!(verify_signature(dek, &empty_header))
    }

    #[test]
    fn verify_empty_sig_v3_header() {
        // {
        //   "sig": [],
        //   "saas_shield": {
        //     "tenant_id": "tenantId"
        //   }
        // }
        let proto_bytes = hex!("0a001a0a0a0874656e616e744964");
        let dek: [u8; 32] = (0..32).into_iter().collect_vec().try_into().unwrap();
        let header = Message::parse_from_bytes(&proto_bytes).unwrap();
        assert!(verify_signature(dek, &header));
    }

    #[test]
    fn decompose_signature_works() {
        let sig_1 = (0..28).collect_vec();
        let decomposed_1 = decompose_signature(&sig_1.into()).unwrap();
        let expected_iv_1 = (0..12).collect_vec();
        let expected_tag_1 = (12..28).collect_vec();
        assert_eq!(&decomposed_1.iv[..], expected_iv_1);
        assert_eq!(&decomposed_1.gcm_tag[..], expected_tag_1);

        let sig_2 = (0..100).collect_vec();
        let decomposed_2 = decompose_signature(&sig_2.into()).unwrap();
        let expected_iv_2 = (0..12).collect_vec();
        let expected_tag_2 = (84..100).collect_vec();
        assert_eq!(&decomposed_2.iv[..], expected_iv_2);
        assert_eq!(&decomposed_2.gcm_tag[..], expected_tag_2);

        let sig_3 = (0..10).collect_vec();
        let decomposed_failure = decompose_signature(&sig_3.into());
        assert!(decomposed_failure.is_none());
    }
}
