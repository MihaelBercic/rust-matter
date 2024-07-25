#![allow(unused)]
#![allow(dead_code)]

use std::net::UdpSocket;
use std::ops::Add;
use std::sync::Mutex;

use matter::constants::PROTOCOL;
use matter::mdns::enums::{CommissionState, DeviceType};
use matter::mdns::service::MDNSService;
use matter::service::enums::MatterDestinationID::Node;
use matter::service::enums::MatterDeviceState;
use matter::service::message::MatterMessage;
use matter::service::message_builder::MatterMessageBuilder;
use matter::service::protocol::communication::counters::{GLOBAL_UNENCRYPTED_COUNTER, initialize_counter};
use matter::service::protocol::message::ProtocolMessage;
use matter::service::protocol::message_builder::ProtocolMessageBuilder;

const CURRENT_STATE: Mutex<MatterDeviceState> = Mutex::new(MatterDeviceState::Unpaired);

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
        let (size, socket) = udp_socket.recv_from(&mut b).unwrap();
        println!("Received {} data on UDP socket...", size);
        // println!("const FIRST_PACKET_SAMPLE: [u8; {}] = [{}];", size, &b[..size].iter().map(|x| format!("0x{:02x}", x).to_string()).collect::<Vec<String>>().join(","));
        let matter_message = MatterMessage::try_from(&b[..size]);
        match matter_message {
            Ok(matter) => {
                let protocol_message = ProtocolMessage::try_from(&matter.payload[..]);
                match protocol_message {
                    Ok(message) => {
                        println!("Needs ack: {}", message.exchange_flags.needs_acknowledgement());
                        if message.exchange_flags.needs_acknowledgement() {
                            let protocol_message = ProtocolMessageBuilder::new()
                                .set_acknowledged_message_counter(message.acknowledged_message_counter)
                                .build();
                            let matter_message = MatterMessageBuilder::new()
                                .set_destination(Node(matter.header.source_node_id.unwrap()))
                                .set_payload(&protocol_message.as_bytes()[..])
                                .build();
                            udp_socket.send_to(&matter_message.to_bytes()[..], socket);
                        }
                    }
                    Err(error) => println!("Yikes: {:?}", error)
                };
            }
            Err(error) => {
                println!("Yikes {:?}", error);
            }
        }
    }
}