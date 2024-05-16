use std::net::UdpSocket;
use std::ops::Add;

use matter::discovery::constants::*;
use matter::discovery::mdns_service::{CommissionState, DeviceType, MDNSService};
use matter::service::protocol::communication::counters::{GLOBAL_UNENCRYPTED_COUNTER, initialize_counter};
use matter::service::structs::MatterMessage;

fn main() {
    initialize_counter(&mut GLOBAL_UNENCRYPTED_COUNTER);


    let interface = netif::up().unwrap().find(|x| x.name() == "en7").unwrap();

    let my_ip = "fdc3:de31:45b5:c843:14aa:95ef:2844:22e".to_string();
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
    loop {
        println!("Listening on: {:?}", &udp_socket.local_addr());
        let (size, remote) = udp_socket.recv_from(&mut b).unwrap();
        println!("Received {} data on UDP socket...", size);
        let matter_message = MatterMessage::try_from(&b[..size]);
        match matter_message {
            Ok(matter) => {
                println!("Successfully parsed matter message! => {}", String::from_utf8_lossy(&matter.integrity_check));
            }
            Err(error) => {
                println!("Yikes {:?}", error);
            }
        }
    }
}
