use p256::ecdsa::SigningKey;

use crate::{
    mdns::enums::{CommissionState, DeviceType},
    session::protocol::interaction::cluster::FabricDescriptor,
};
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
    pub nocs: Vec<SigningKey>,
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
