use matter::mdns::enums::{CommissionState, DeviceType};
use matter::mdns::mdns_device_information::MDNSDeviceInformation;
use matter::NetworkInterface;
use std::collections::HashMap;
use std::net::Ipv6Addr;
use std::str::FromStr;

#[derive(Debug)]
struct Test {
    id: u8,
}

fn main() {
    let mut map: HashMap<u8, Test> = HashMap::new();
    map.insert(0, Test { id: 0 });
    let test = map.get_mut(&0).unwrap();
    test.id = 1;
    println!("{:?}", map);

    let is_eth = true;
    let mut interface = NetworkInterface { index: 0xe, do_custom: false };         // WiFi
    let mut ip = Ipv6Addr::from_str("fe80::1008:fc1d:3b7c:eda9").unwrap();
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