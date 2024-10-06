use matter::mdns::enums::{CommissionState, DeviceType};
use matter::mdns::mdns_device_information::MDNSDeviceInformation;
use matter::session::protocol::interaction::cluster::{BasicInformationCluster, Device, GeneralCommissioningCluster, NetworkCommissioningCluster};
use matter::session::protocol::interaction::enums::ClusterID::{BasicInformation, GeneralCommissioning, NetworkCommissioning};
use matter::NetworkInterface;
use std::net::Ipv6Addr;
use std::str::FromStr;

fn main() {
    let is_eth = true;
    let mut interface = NetworkInterface { index: 0xe, do_custom: true };         // WiFi
    let mut ip = Ipv6Addr::from_str("fe80::1828:f752:3892:a05b").unwrap();
    if is_eth {
        interface = NetworkInterface { index: 0xf, do_custom: true };         // Eth   en7
        ip = Ipv6Addr::from_str("fe80::14c8:e38a:e7b2:673c").unwrap();
    }

    let mac: [u8; 6] = [0xFF, 0x32, 0x11, 0x4, 0x2, 0x99];
    let device_information = MDNSDeviceInformation {
        ip,
        mac,
        device_name: "thermostat".to_string(),
        device_type: DeviceType::Light,
        discriminator: DeviceType::Thermostat as u16,
        commission_state: CommissionState::NotCommissioned,
        vendor_id: 0xFFF1,
        product_id: 0x8000,
    };

    let basic = BasicInformationCluster::new();
    let mut device = Device::new();
    device.insert(0, BasicInformation, BasicInformationCluster::new());
    device.insert(0, GeneralCommissioning, GeneralCommissioningCluster::new());
    device.insert(0, NetworkCommissioning, NetworkCommissioningCluster::new());
    matter::start(device_information, interface, device);
}