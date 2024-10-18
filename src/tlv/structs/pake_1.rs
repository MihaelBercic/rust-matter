use crate::crypto::constants::CRYPTO_PUBLIC_KEY_SIZE_BYTES;
use crate::tlv::element_type::ElementType;
use crate::tlv::tlv::Tlv;
use crate::utils::MatterError;
use crate::utils::MatterLayer::Application;

///
/// @author Mihael Berčič
/// @date 7. 8. 24
///
#[derive(Debug, Clone)]
pub struct Pake1 {
    pub p_a: [u8; CRYPTO_PUBLIC_KEY_SIZE_BYTES],
}

impl TryFrom<Tlv> for Pake1 {
    type Error = MatterError;

    fn try_from(value: Tlv) -> Result<Self, Self::Error> {
        if let ElementType::Structure(children) = value.control.element_type {
            for child in children {
                let p_a_vec = child.control.element_type.into_octet_string()?;
                return Ok(Self {
                    p_a: p_a_vec.try_into().unwrap(),
                });
            }
        }
        Err(MatterError::new(Application, "Boo"))
    }
}
