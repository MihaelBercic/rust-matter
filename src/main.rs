use matter::mdns::enums::{CommissionState, DeviceType};
use matter::{MDNSDeviceInformation, NetworkInterface};
use std::net::Ipv6Addr;
use std::str::FromStr;

fn main() {
    // let udp = UdpSocket::bind("[::]:0").unwrap();
    // println!("Listening on {:?}", udp.local_addr().unwrap().port());
    // let mut buffer = [0u8; 1000];
    // loop {
    //     let (size, sender) = udp.recv_from(&mut buffer).unwrap();
    //     println!("Data of size {} from {:?} => {}", size, sender, String::from_utf8_lossy(&buffer[..size]))
    // }
    //
    // return;
    let interface = NetworkInterface { index: 0x1D, do_custom: true };
    let ip = Ipv6Addr::from_str("fe80::8a5:5eff:ed1c:c07b").unwrap();
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
    matter::start(&device, interface);
}