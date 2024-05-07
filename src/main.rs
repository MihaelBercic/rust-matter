use std::collections::HashMap;
use std::io::{stdout, Write};
use std::net::UdpSocket;
use std::ops::Add;
use std::str::FromStr;
use std::thread;
use std::time::Duration;

use crate::discovery::constants::{MDNS_PORT, PROTOCOL};
use crate::discovery::mdns::multicast_socket::MulticastSocket;
use crate::discovery::mdns::structs::{CompleteRecord, MDNSPacket, MDNSPacketHeader, RecordInformation, RecordType};

mod discovery;
mod useful;

fn main() {
    let interface = netif::up().unwrap().find(|x| x.name() == "en7").unwrap();
    let mut socket = MulticastSocket::new(&interface, MDNS_PORT);
    let my_ip = "fdc3:de31:45b5:c843:14aa:95ef:2844:22e";

    let mac: [u8; 6] = [0xFF, 0x32, 0x11, 0x4, 0x2, 0x99];
    let mac_hex = hex::encode_upper(mac);
    let host_name = mac_hex.add(".local");
    let device_name = "thermostat.".to_string().add(PROTOCOL);
    let udp_socket = UdpSocket::bind("[::]:0").expect("Unable to bind to tcp...");

    let ptr_record = CompleteRecord {
        record_information: RecordInformation {
            label: PROTOCOL.to_string(),
            record_type: RecordType::PTR,
            flags: 1,
            class_code: 1,
            has_property: true,
        },
        ttl: 90,
        data: PTRRecord { domain: device_name.clone() }.into(),
    };
    let srv_record = CompleteRecord {
        record_information: RecordInformation {
            label: device_name.clone(),
            record_type: RecordType::SRV,
            flags: 0,
            class_code: 1,
            has_property: false,
        },
        ttl: 90,
        data: SRVRecord {
            target: host_name.clone(),
            priority: 0,
            weight: 0,
            port: udp_socket.local_addr().unwrap().port(),
        }.into(),
    };
    let aaaa_record = CompleteRecord {
        record_information: RecordInformation {
            label: host_name.clone(),
            record_type: RecordType::AAAA,
            flags: 0,
            class_code: 1,
            has_property: false,
        },
        ttl: 90,
        data: AAAARecord { address: my_ip.to_string() }.into(),
    };

    let mut map: HashMap<String, String> = HashMap::new();
    map.insert("D".to_string(), "3".to_string());
    map.insert("CM".to_string(), "2".to_string());
    map.insert("DT".to_string(), "301".to_string()); // Thermostat device type.
    map.insert("DN".to_string(), "Termostat".to_string());
    // map.insert("VP".to_string(), "0xFFF1".to_string());

    let txt_record = CompleteRecord {
        record_information: RecordInformation {
            label: device_name.clone(),
            record_type: RecordType::TXT,
            flags: 0,
            class_code: 1,
            has_property: false,
        },
        ttl: 90,
        data: TXTRecord { map }.into(),
    };

    let my_packet = MDNSPacket {
        header: MDNSPacketHeader::new_with_flags(1, true, 0, false, false),
        query_records: vec![],
        answer_records: vec![ptr_record],
        additional_records: vec![srv_record, aaaa_record, txt_record],
        authority_records: vec![],
    };
    let buffer: Vec<u8> = my_packet.into();
    thread::spawn(move || {
        let mut b = [0u8; 1000];
        loop {
            println!("Listening on: {:?}", udp_socket.local_addr());
            let (size, remote) = udp_socket.recv_from(&mut b).unwrap();
            println!("Received {} data on UDP socket...", size);
        }
    });

    let mut total = 0usize;
    let mut failed = 0usize;
    loop {
        let (size, sender) = socket.receive_from().unwrap();
        let data = &socket.buffer[0..size];
        match MDNSPacket::try_from(data) {
            Ok(packet) => {
                total += 1;
                let is_unicast = packet.query_records.iter().any(|q| q.has_property);
                if packet.query_records.iter().any(|q| q.label.contains("matter")) {
                    thread::sleep(Duration::from_millis(150));
                    if (is_unicast) {
                        socket.udp_socket.send_to(&buffer, sender).unwrap();
                    } else {
                        socket.udp_socket.send_to(&buffer, format!("FF02::FB%{}:5353", &interface.name())).unwrap();
                    }
                    thread::sleep(Duration::from_millis(200));
                    // println!("Responding to both");
                }
            }
            Err(_) => {
                failed += 1;
            }
        }
        print!("\rTotal: {}\tFailed {}", format!("{:5}", total), format!("{:5}", failed));
        stdout().flush().unwrap();
    }
}
