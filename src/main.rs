use matter::mdns::enums::{CommissionState, DeviceType};
use matter::mdns::mdns_device_information::MDNSDeviceInformation;
use matter::session::protocol::interaction;
use matter::session::protocol::interaction::cluster;
use matter::session::protocol::interaction::cluster::basic_information::BasicInformationCluster;
use matter::session::protocol::interaction::cluster::general_commissioning::GeneralCommissioningCluster;
use matter::session::protocol::interaction::cluster::network_commissioning::NetworkCommissioningCluster;
use matter::session::protocol::interaction::cluster::operational_credentials::OperationalCredentialsCluster;
use matter::session::protocol::interaction::enums::ClusterID::{
    BasicInformation, Descriptor, GeneralCommissioning, NetworkCommissioning, OnOff, OperationalCredentials,
};
use matter::session::Device;
use matter::NetworkInterface;
use std::net::Ipv6Addr;
use std::str::FromStr;

fn main() {
    let is_eth = true;
    let mut interface = NetworkInterface { index: 0xe, do_custom: true }; // WiFi
    let mut ip = Ipv6Addr::from_str("fe80::1828:f752:3892:a05b").unwrap();
    if is_eth {
        interface = NetworkInterface {
            index: 0x10,
            do_custom: true,
        }; // Eth   en7
        ip = Ipv6Addr::from_str("fe80::457:b3cc:da39:9caf").unwrap();
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

    let mut device = Device::new();
    device.insert(0, BasicInformation, BasicInformationCluster::new());
    device.insert(0, GeneralCommissioning, GeneralCommissioningCluster::new());
    device.insert(0, NetworkCommissioning, NetworkCommissioningCluster::new());
    device.insert(0, OperationalCredentials, OperationalCredentialsCluster::new());
    device.insert(0, Descriptor, interaction::cluster::descriptor_cluster::DescriptorCluster::new());

    device.insert(1, OnOff, cluster::on_off::OnOffCluster::new());

    device.modify_cluster::<NetworkCommissioningCluster>(0, NetworkCommissioning, |cluster| {
        cluster.connect();
    });
    matter::start(device_information, interface, device);
}
