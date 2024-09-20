use matter::mdns::enums::{CommissionState, DeviceType};
use matter::mdns::mdns_device_information::MDNSDeviceInformation;
use matter::NetworkInterface;
use std::net::Ipv6Addr;
use std::str::FromStr;

fn main() {
    let is_eth = false;
    let mut interface = NetworkInterface { index: 0xe, do_custom: true };         // WiFi
    let mut ip = Ipv6Addr::from_str("fe80::1828:f752:3892:a05b").unwrap();
    if is_eth {
        interface = NetworkInterface { index: 0x10, do_custom: true };         // Eth   en7
        ip = Ipv6Addr::from_str("fe80::46b:7b03:a627:8239").unwrap();
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