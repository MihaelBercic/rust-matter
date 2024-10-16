use crate::mdns::enums::{CommissionState, DeviceType};
use std::net::Ipv6Addr;

///
/// @author Mihael Berčič
/// @date 15. 9. 24
///
pub struct MDNSDeviceInformation {
    pub ip: Ipv6Addr,
    pub mac: [u8; 6],
    pub device_name: String,
    pub device_type: DeviceType,
    pub discriminator: u16, // Still don't know how this is supposed to be computed.
    pub commission_state: CommissionState,
    pub vendor_id: u16,
    pub product_id: u16,
}

