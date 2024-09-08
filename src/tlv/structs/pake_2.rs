use crate::crypto::constants::{CRYPTO_HASH_LEN_BYTES, CRYPTO_PUBLIC_KEY_SIZE_BYTES};
use crate::tlv::element_type::ElementType::{OctetString8, Structure};
use crate::tlv::tag_control::TagControl::ContextSpecific8;
use crate::tlv::tag_number::TagNumber::Short;
use crate::tlv::tlv::TLV;
use crate::tlv::{create_advanced_tlv, create_tlv};

///
/// @author Mihael Berčič
/// @date 19. 8. 24
///
pub struct Pake2 {
    pub(crate) p_b: [u8; CRYPTO_PUBLIC_KEY_SIZE_BYTES],
    pub(crate) c_b: [u8; CRYPTO_HASH_LEN_BYTES],
}

impl Into<TLV> for Pake2 {
    fn into(self) -> TLV {
        let mut children = vec![
            create_advanced_tlv(OctetString8(self.p_b.to_vec()), ContextSpecific8, Some(Short(1)), None, None),
            create_advanced_tlv(OctetString8(self.c_b.to_vec()), ContextSpecific8, Some(Short(2)), None, None),
        ];
        create_tlv(Structure(children))
    }
}