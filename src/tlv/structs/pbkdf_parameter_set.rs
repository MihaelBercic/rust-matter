use crate::tlv::element_type::ElementType::Structure;
use crate::tlv::tag::Tag;
use crate::tlv::tag_control::TagControl::ContextSpecific8;
use crate::tlv::tlv::Tlv;

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
impl From<PBKDFParameterSet> for Tlv {
    fn from(value: PBKDFParameterSet) -> Self {
        Tlv::simple(Structure(vec![
            Tlv::new(value.iterations.into(), ContextSpecific8, Tag::short(1)),
            Tlv::new(value.salt.into(), ContextSpecific8, Tag::short(2)),
        ]))
    }
}
