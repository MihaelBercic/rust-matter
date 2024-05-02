use std::collections::HashMap;
use std::net::TcpListener;
use std::ops::Add;
use std::thread;
use std::time::Duration;

use crate::discovery::constants::{MDNS_PORT, PROTOCOL};
use crate::discovery::mdns::mdns_structs::{CompleteRecord, MDNSPacket, MDNSPacketHeader, RecordInformation, RecordType};
use crate::discovery::mdns::multicast_socket::MulticastSocket;
use crate::discovery::mdns::records::aaaa_record::AAAARecord;
use crate::discovery::mdns::records::ptr_record::PTRRecord;
use crate::discovery::mdns::records::srv_record::SRVRecord;
use crate::discovery::mdns::records::txt_record::TXTRecord;

mod discovery;
mod useful;

fn main() {
    let interface = netif::up().unwrap().find(|x| x.name() == "en0").unwrap();
    let mut socket = MulticastSocket::new(interface, MDNS_PORT);

    let mac: [u8; 6] = [0xFF, 0x32, 0x11, 0x4, 0x2, 0x99];
    let mac_hex = hex::encode_upper(mac);
    let host_name = mac_hex.add(".local");
    let device_name = "thermostat.".to_string().add(PROTOCOL);
    let tcp_socket = TcpListener::bind("[::]:0").expect("Unable to bind to tcp...");
    println!("{}", host_name);

    let mut buffer: Vec<u8> = vec![];
    //     private val srvRecord = SRVRecord(recordName, targetName, settings.port, timeToLive = 4500, isCached = false)
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
            port: tcp_socket.local_addr().unwrap().port(),
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
        data: AAAARecord { address: "fdc3:de31:45b5:c843:14aa:95ef:2844:22e".to_string() }.into(),
    };

    let mut map: HashMap<String, String> = HashMap::new();
    map.insert("D".to_string(), "840".to_string());
    map.insert("CM".to_string(), "2".to_string());
    map.insert("DT".to_string(), "301".to_string());
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
        header: MDNSPacketHeader {
            identification: 0,
            flags: 0,
            is_response: true,
            opcode: 0,
            is_authoritative_answer: false,
            is_truncated: false,
            is_recursion_desired: false,
            is_recursion_available: false,
            response_code: 0,
        },
        query_records: vec![],
        answer_records: vec![ptr_record],
        additional_records: vec![srv_record, aaaa_record, txt_record],
        authority_records: vec![],
    };

    let buffer: Vec<u8> = my_packet.into();
    let as_binary: Vec<String> = buffer.clone().iter().map(|b| format!("{:08b}", b)).collect();
    // println!("{}", as_binary.join(" "));
    // println!("{}", String::from_utf8_lossy(&buffer));

    socket.udp_socket.send_to(&buffer, "FF02::FB%en0:5353").unwrap();

    thread::spawn(move || {
        loop {
            let (stream, remote) = tcp_socket.accept().unwrap();
            println!("Connected socket: {}", remote)
        }
    });

    loop {
        let (size, sender) = socket.receive_from().unwrap();
        let data = &socket.buffer[0..size];
        // println!("{}", String::from_utf8_lossy(data));
        // let code = data
        //     .iter()
        //     .map(|x| format!("{:#04x}", x))
        //     .collect::<Vec<String>>()
        //     .join(",");
        // let sample = String::from_utf8_lossy(data);
        // println!("Message from {} IS ME?? {}", sender, sender.ip().to_string().contains("fdc3"));
        let packet = MDNSPacket::from(data);
        let is_unicast = packet.query_records.iter().any(|q| q.has_property);
        if packet.query_records.iter().any(|q| q.label.contains("matter")) {
            println!("Is unicast: {} => {:?}", is_unicast, sender);
            // println!("{}", sample);
            // println!(": [u8;{}] = [{}]", size, code);
            thread::sleep(Duration::from_millis(150));
            socket.udp_socket.send_to(&buffer, sender).unwrap();
            thread::sleep(Duration::from_millis(200));
            // socket.udp_socket.send_to(&buffer, "FF02::FB%en0:5353").unwrap();
            println!("Responding to both");
        } else {}
        drop(packet);
    }
}
