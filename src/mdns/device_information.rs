use crate::{
    mdns::enums::{CommissionState, DeviceType},
    tlv::{element_type::ElementType, tag::Tag, tag_control::TagControl, tlv::Tlv},
};
use p256::ecdsa::SigningKey;
use std::net::Ipv6Addr;

///
/// @author Mihael Berčič
/// @date 15. 9. 24
///
pub struct Details {
    pub ip: Ipv6Addr,
    pub mac: [u8; 6],
    pub device_name: String,
    pub device_type: DeviceType,
    pub discriminator: u16,
    pub commission_state: CommissionState,
    pub vendor_id: u16,
    pub product_id: u16,
    pub advertise: bool,
    pub instance_name: String,
    pub host_name: String,
    pub nocs: Vec<NOC>,
    pub trusted_root_certificates: Vec<Vec<u8>>,
    pub group_keys: Vec<GroupKey>,
    pub compressed_fabric_ids: Vec<Vec<u8>>,
    pub fabrics: Vec<FabricDescriptor>,
}

pub enum GroupKeySecurityPolicy {
    TrustFirst = 0,
    CacheAndSync = 1,
}

pub enum GroupKeyMulticastPolicy {
    PerGroupId = 0,
    AllNodes = 1,
}

pub struct GroupKey {
    pub id: u8,
    pub security_policy: GroupKeySecurityPolicy,
    pub epoch_key: Vec<u8>,
    pub epoch_start_time: u128,
}

/// `noc`: Node Operational Certificate
///
/// `icac`: Intermediate Certificate Authority Certificate
#[derive(Clone, Debug)]
pub struct NOC {
    pub icac: Option<Vec<u8>>,
    pub noc: Vec<u8>,
    pub private_key: SigningKey,
}

#[derive(Debug, Clone)]
pub struct FabricDescriptor {
    pub root_public_key: Vec<u8>,
    pub vendor_id: u16,
    pub fabric_id: u64,
    pub node_id: u64,
    pub label: String,
}

impl From<FabricDescriptor> for ElementType {
    fn from(value: FabricDescriptor) -> Self {
        let children: Vec<Tlv> = vec![
            Tlv::new(value.root_public_key.into(), TagControl::ContextSpecific8, Tag::short(1)),
            Tlv::new(value.vendor_id.into(), TagControl::ContextSpecific8, Tag::short(2)),
            Tlv::new(value.fabric_id.into(), TagControl::ContextSpecific8, Tag::short(3)),
            Tlv::new(value.node_id.into(), TagControl::ContextSpecific8, Tag::short(4)),
            Tlv::new(value.label.into(), TagControl::ContextSpecific8, Tag::short(5)),
        ];
        ElementType::Structure(children)
    }
}

impl From<Vec<FabricDescriptor>> for ElementType {
    fn from(value: Vec<FabricDescriptor>) -> Self {
        let mut vec = vec![];
        for x in value {
            vec.push(Tlv::simple(x.into()))
        }
        ElementType::List(vec)
    }
}
