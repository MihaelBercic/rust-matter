use crate::tlv::element_type::ElementType::Structure;
use crate::tlv::tag::Tag;
use crate::tlv::tag_control::TagControl::ContextSpecific8;
use crate::tlv::tag_number::TagNumber;
use crate::tlv::tlv::TLV;

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
        TLV::simple(Structure(vec![
            TLV::new(value.iterations.into(), ContextSpecific8, Tag::short(1)),
            TLV::new(value.salt.into(), ContextSpecific8, Tag::short(2)),
        ]))
    }
}
