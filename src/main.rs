use matter::mdns::enums::{CommissionState, DeviceType};
use matter::mdns::mdns_device_information::MDNSDeviceInformation;
use matter::NetworkInterface;
use std::net::Ipv6Addr;
use std::str::FromStr;

fn main() {
    let is_eth = true;
    let mut interface = NetworkInterface { index: 0xf, do_custom: true };         // WiFi
    let mut ip = Ipv6Addr::from_str("fe80::1008:fc1d:3b7c:eda9").unwrap();
    if is_eth {
        interface = NetworkInterface { index: 0x1D, do_custom: true };         // Eth
        ip = Ipv6Addr::from_str("fe80::8a5:5eff:ed1c:c07b").unwrap();
    }

    let mac: [u8; 6] = [0xFF, 0x32, 0x11, 0x4, 0x2, 0x99];

    let device = MDNSDeviceInformation {
        ip,
        mac,
        device_name: "thermostat".to_string(),
        device_type: DeviceType::Light,
        discriminator: DeviceType::Thermostat as u16,
        commission_state: CommissionState::InCommissioning,
        vendor_id: 0xFFF1,
        product_id: 0x8000,
    };
    matter::start(device, interface);
}