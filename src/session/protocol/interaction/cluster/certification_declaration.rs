use crate::tlv::{element_type::ElementType, tag::Tag, tag_control::TagControl::ContextSpecific8, tlv::TLV};

pub struct CertificationDeclaration {
    pub format_version: u16,
    pub vendor_id: u16,
    pub product_id: Vec<u16>,
    pub device_type_id: u32,
    pub certificate_id: String,
    pub security_level: u8,
    pub security_information: u16,
    pub version_number: u16,
    pub certification_type: u8,
    pub dac_origin_vendor_id: Option<u16>,
    pub dac_origin_product_id: Option<u16>,
    // ToDo: Add later... authorized_paa_list: Option<[[u8; 20]; 10]>,
}

impl CertificationDeclaration {
    pub fn new() -> Self {
        Self {
            format_version: 1,
            vendor_id: 0xFFF1,
            product_id: vec![0x8000],
            device_type_id: 22,
            certificate_id: "CSA00000SWC00000-00".to_string(),
            security_level: 0,
            security_information: 0,
            version_number: 1,
            certification_type: 0, // 0 = Test, 1 = Provisional/In certification, 2 = official
            dac_origin_vendor_id: None,
            dac_origin_product_id: None,
        }
    }
}

impl From<CertificationDeclaration> for ElementType {
    fn from(value: CertificationDeclaration) -> Self {
        let mut vec = vec![
            TLV::new(value.format_version.into(), ContextSpecific8, Tag::short(0)),
            TLV::new(value.vendor_id.into(), ContextSpecific8, Tag::short(1)),
            TLV::new(value.product_id.into(), ContextSpecific8, Tag::short(2)),
            TLV::new(value.device_type_id.into(), ContextSpecific8, Tag::short(3)),
            TLV::new(value.certificate_id.into(), ContextSpecific8, Tag::short(4)),
            TLV::new(value.security_level.into(), ContextSpecific8, Tag::short(5)),
            TLV::new(value.security_information.into(), ContextSpecific8, Tag::short(6)),
            TLV::new(value.version_number.into(), ContextSpecific8, Tag::short(7)),
            TLV::new(value.certification_type.into(), ContextSpecific8, Tag::short(8)),
        ];
        if value.dac_origin_vendor_id.is_some() {
            vec.push(TLV::new(value.dac_origin_vendor_id.unwrap().into(), ContextSpecific8, Tag::short(9)))
        };
        if value.dac_origin_product_id.is_some() {
            vec.push(TLV::new(value.dac_origin_product_id.unwrap().into(), ContextSpecific8, Tag::short(10)))
        };
        // if true { vec.push(TLV::new(value.authorized_paa_list.into(), ContextSpecific8, Tag::simple(Short(11)))};
        ElementType::Structure(vec)
    }
}
