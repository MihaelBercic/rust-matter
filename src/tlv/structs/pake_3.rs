use crate::crypto::constants::CRYPTO_HASH_LEN_BYTES;
use crate::tlv::element_type::ElementType::Structure;
use crate::tlv::tag_number::TagNumber::Short;
use crate::tlv::tlv::TLV;
use crate::utils::{MatterError, MatterLayer};
use std::alloc::GlobalAlloc;

///
/// @author Mihael Berčič
/// @date 15. 9. 24
///
pub struct Pake3 {
    pub c_a: [u8; CRYPTO_HASH_LEN_BYTES],
}

impl TryFrom<TLV> for Pake3 {
    type Error = MatterError;

    fn try_from(value: TLV) -> Result<Self, Self::Error> {
        if let Structure(children) = value.control.element_type {
            for child in children {
                if let Some(Short(1)) = child.tag.tag_number {
                    return Ok(
                        Self {
                            c_a: child.control.element_type.into_octet_string()?.try_into()?
                        }
                    );
                }
            }
        }
        Err(MatterError::new(MatterLayer::SecureSession, "Not correct TLV format of PAKE3."))
    }
}

