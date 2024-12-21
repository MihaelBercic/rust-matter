use crate::{
    tlv::{element_type::ElementType, tag_number::TagNumber, tlv::Tlv},
    utils::{bail_tlv, MatterError},
};

/// Core spec v1.2 - Page 317 - 6.5.2
pub struct MatterCertificate {
    pub serial_number: Vec<u8>,
    pub ec_public_key: Vec<u8>,
    pub subject: DnAttribute,
}

impl TryFrom<&[u8]> for MatterCertificate {
    type Error = MatterError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let tlv = Tlv::try_from(value)?;
        let mut certificate = Self {
            serial_number: vec![],
            ec_public_key: vec![],
            subject: DnAttribute {
                matter_fabric_id: 0,
                matter_node_id: 0,
            },
        };

        let ElementType::Structure(children) = tlv.control.element_type else {
            bail_tlv!("Incorrect certificate tlv structure.")
        };

        for child in children {
            let element_type = child.control.element_type;
            let Some(TagNumber::Short(tag_number)) = child.tag.tag_number else {
                bail_tlv!("Missing tag number")
            };
            match tag_number {
                1 => certificate.serial_number = element_type.into_octet_string()?,
                6 => certificate.subject = DnAttribute::try_from(element_type)?,
                9 => certificate.ec_public_key = element_type.into_octet_string()?,
                _ => (), // log_info!("Tag {} not implemented yet.", tag_number)),
            }
        }

        Ok(certificate)
    }
}

pub struct DnAttribute {
    pub matter_fabric_id: u64,
    pub matter_node_id: u64,
}

impl TryFrom<ElementType> for DnAttribute {
    type Error = MatterError;

    fn try_from(value: ElementType) -> Result<Self, Self::Error> {
        let ElementType::List(children) = value else {
            bail_tlv!("Incorrect data structure.");
        };
        let mut dn = Self {
            matter_fabric_id: 0,
            matter_node_id: 0,
        };

        for child in children {
            let element = child.control.element_type;
            let Some(TagNumber::Short(tag_number)) = child.tag.tag_number else {
                bail_tlv!("Missing tag number...");
            };
            match tag_number {
                17 => dn.matter_node_id = element.into_u64()?,
                21 => dn.matter_fabric_id = element.into_u64()?,
                _ => (), // log_debug!("Tag number {} Not implemented.", tag_number)),
            }
        }
        Ok(dn)
    }
}
