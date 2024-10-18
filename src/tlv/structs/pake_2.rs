use crate::crypto::constants::{CRYPTO_HASH_LEN_BYTES, CRYPTO_PUBLIC_KEY_SIZE_BYTES};
use crate::tlv::element_type::ElementType::Structure;
use crate::tlv::tag::Tag;
use crate::tlv::tag_control::TagControl::ContextSpecific8;
use crate::tlv::tag_number::TagNumber::Short;
use crate::tlv::tlv::Tlv;

///
/// @author Mihael Berčič
/// @date 19. 8. 24
///
#[derive(Debug, Clone)]
pub struct Pake2 {
    pub(crate) p_b: [u8; CRYPTO_PUBLIC_KEY_SIZE_BYTES],
    pub(crate) c_b: [u8; CRYPTO_HASH_LEN_BYTES],
}

impl From<Pake2> for Tlv {
    fn from(value: Pake2) -> Self {
        Tlv::simple(Structure(vec![
            Tlv::new(value.p_b.into(), ContextSpecific8, Tag::short(1)),
            Tlv::new(value.c_b.into(), ContextSpecific8, Tag::short(2)),
        ]))
    }
}
