#![allow(unused)]
#![allow(dead_code)]

use std::net::UdpSocket;
use std::ops::Add;

use matter::constants::PROTOCOL;
use matter::discovery::enums::{CommissionState, DeviceType};
use matter::discovery::mdns::service::MDNSService;
use matter::service::message::MatterMessage;
use matter::service::protocol::communication::counters::{GLOBAL_UNENCRYPTED_COUNTER, initialize_counter};

fn main() {
    initialize_counter(&GLOBAL_UNENCRYPTED_COUNTER);
    let interface = netif::up().unwrap().find(|x| x.name() == "en0").unwrap();
    let my_ip = "fdc3:de31:45b5:c843:14aa:95ef:2844:22e".to_string();
    let my_ip = "fdc3:de31:45b5:c843:89:981b:33af:57d2".to_string();
    let mac: [u8; 6] = [0xFF, 0x32, 0x11, 0x4, 0x2, 0x99];
    let mac_hex = hex::encode_upper(mac);
    let host_name = mac_hex.add(".local");
    let device_name = "thermostat.".to_string().add(PROTOCOL);
    let udp_socket = UdpSocket::bind("[::]:0").expect("Unable to bind to tcp...");

    let mut mdns_service = MDNSService {
        udp_port: udp_socket.local_addr().unwrap().port(),
        ip: my_ip,
        host_name,
        device_name,
        discriminator: 300, // Still don't know how this is supposed to be computed.
        device_type: DeviceType::Thermostat,
        commission_state: CommissionState::NotCommissioned,
        vendor_id: 123,
        product_id: 456,
    };
    mdns_service.start_advertising(&interface);

    let mut b = [0u8; 1000];
    println!("Listening on: {:?}", &udp_socket.local_addr());
    loop {
        let (size, _) = udp_socket.recv_from(&mut b).unwrap();
        println!("Received {} data on UDP socket...", size);
        println!("const FIRST_PACKET_SAMPLE: [u8; {}] = [{}];", size, &b[..size].iter().map(|x| format!("0x{:02x}", x).to_string()).collect::<Vec<String>>().join(","));
        let matter_message = MatterMessage::try_from(&b[..size]);
        match matter_message {
            Ok(matter) => {}
            Err(error) => {
                println!("Yikes {:?}", error);
            }
        }
    }
}