use crate::crypto::constants::CRYPTO_PUBLIC_KEY_SIZE_BYTES;
use crate::tlv::element_type::ElementType;
use crate::tlv::element_type::ElementType::OctetString8;
use crate::tlv::tlv::TLV;
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

impl TryFrom<TLV> for Pake1 {
    type Error = MatterError;

    fn try_from(value: TLV) -> Result<Self, Self::Error> {
        if let ElementType::Structure(children) = value.control.element_type {
            for child in children {
                if let OctetString8(bytes) = child.control.element_type {
                    let mut p_a = [0u8; CRYPTO_PUBLIC_KEY_SIZE_BYTES];
                    if bytes.len() == p_a.len() {
                        p_a.copy_from_slice(&bytes);
                        return Ok(Self { p_a });
                    }
                }
            }
        }
        Err(MatterError::new(Application, "Boo"))
    }
}

