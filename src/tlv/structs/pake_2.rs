use crate::crypto::constants::{CRYPTO_HASH_LEN_BYTES, CRYPTO_PUBLIC_KEY_SIZE_BYTES};
use crate::tlv::element_type::ElementType::Structure;
use crate::tlv::tag_control::TagControl::ContextSpecific8;
use crate::tlv::tag_number::TagNumber::Short;
use crate::tlv::tlv::TLV;
use crate::tlv::{create_advanced_tlv, create_tlv, tlv_octet_string};

///
/// @author Mihael Berčič
/// @date 19. 8. 24
///
#[derive(Debug, Clone)]
pub struct Pake2 {
    pub(crate) p_b: [u8; CRYPTO_PUBLIC_KEY_SIZE_BYTES],
    pub(crate) c_b: [u8; CRYPTO_HASH_LEN_BYTES],
}

impl Into<TLV> for Pake2 {
    fn into(self) -> TLV {
        create_tlv(Structure(vec![
            create_advanced_tlv(tlv_octet_string(&self.p_b), ContextSpecific8, Some(Short(1)), None, None),
            create_advanced_tlv(tlv_octet_string(&self.c_b), ContextSpecific8, Some(Short(2)), None, None),
        ]))
    }
}