use crate::tlv::element_type::ElementType::Structure;
use crate::tlv::tag_control::TagControl::ContextSpecific8;
use crate::tlv::tag_number::TagNumber;
use crate::tlv::tlv::TLV;
use crate::tlv::{create_advanced_tlv, create_tlv, tlv_octet_string, tlv_unsigned};

///
/// @author Mihael Berčič
/// @date 14. 9. 24
///

#[derive(Debug, Clone)]
pub struct PBKDFParameterSet {
    pub iterations: u32,
    pub salt: [u8; 32],
}

/// Computes TLV of the PBKDF Parameter Set using v1.3 specification.
impl From<PBKDFParameterSet> for TLV {
    fn from(value: PBKDFParameterSet) -> Self {
        create_tlv(Structure(vec![
            create_advanced_tlv(tlv_unsigned(value.iterations), ContextSpecific8, Some(TagNumber::Short(1)), None, None),
            create_advanced_tlv(tlv_octet_string(&value.salt), ContextSpecific8, Some(TagNumber::Short(2)), None, None)
        ]))
    }
}

