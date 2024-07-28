use std::io::{stdout, Write};
use std::net::UdpSocket;
use std::ops::Add;
use std::thread;
use std::time::Duration;

use netif::Interface;

use crate::constants::{MDNS_PORT, PROTOCOL};
use crate::mdns::enums::{CommissionState, DeviceType};
use crate::mdns::multicast_socket::MulticastSocket;
use crate::mdns::packet::MDNSPacket;
use crate::mdns::packet_header::MDNSPacketHeader;
use crate::mdns::records::{AAAARecord, PTRRecord, SRVRecord, TXTRecord};
use crate::mdns::records::complete_record::CompleteRecord;
use crate::mdns::records::record_information::RecordInformation;
use crate::mdns::records::record_type::RecordType;
use crate::secure::protocol::communication::counters::{GLOBAL_UNENCRYPTED_COUNTER, initialize_counter};

pub struct MDNSService {
    pub udp_port: u16,
    pub ip: String,
    pub host_name: String,
    pub device_name: String,
    pub discriminator: u16,
    pub device_type: DeviceType,
    pub commission_state: CommissionState,
    pub vendor_id: u16,
    pub product_id: u16,
}

impl MDNSService {
    pub fn start_advertising(&mut self, interface: &Interface) {
        let mut socket = MulticastSocket::new(&interface, MDNS_PORT);
        let ptr_record = CompleteRecord {
            record_information: RecordInformation {
                label: PROTOCOL.to_string(),
                record_type: RecordType::PTR,
                flags: 1,
                class_code: 1,
                has_property: true,
            },
            ttl: 90,
            data: PTRRecord { domain: &self.device_name }.into(),
        };
        let srv_record = CompleteRecord {
            record_information: RecordInformation {
                label: self.device_name.to_string(),
                record_type: RecordType::SRV,
                flags: 0,
                class_code: 1,
                has_property: false,
            },
            ttl: 90,
            data: SRVRecord {
                target: self.host_name.to_string(),
                priority: 0,
                weight: 0,
                port: self.udp_port,
            }.into(),
        };
        let aaaa_record = CompleteRecord {
            record_information: RecordInformation {
                label: self.host_name.to_string(),
                record_type: RecordType::AAAA,
                flags: 0,
                class_code: 1,
                has_property: false,
            },
            ttl: 90,
            data: AAAARecord { address: self.ip.to_string() }.into(),
        };


        let txt_values = format!("D={}\nCM={}\nDT={}\nDN={}\nVP={}+{}",
                                 self.discriminator,
                                 self.commission_state as u8,
                                 self.device_type as u16,
                                 self.device_name,
                                 self.vendor_id,
                                 self.product_id
        );
        println!("{}", txt_values);


        let txt_record = CompleteRecord {
            record_information: RecordInformation {
                label: self.device_name.to_string(),
                record_type: RecordType::TXT,
                flags: 0,
                class_code: 1,
                has_property: false,
            },
            ttl: 90,
            data: TXTRecord { text: txt_values }.into(),
        };

        let packet_response: Vec<u8> = MDNSPacket {
            header: MDNSPacketHeader::new_with_flags(0, true, 0, false, false),
            query_records: vec![],
            answer_records: vec![ptr_record],
            additional_records: vec![srv_record, aaaa_record, txt_record],
            authority_records: vec![],
        }.into();

        let mut _total = 0usize;
        let mut _failed = 0usize;
        let mdns_dst = format!("FF02::FB%{}:5353", &interface.name());
        thread::spawn(move || {
            loop {
                let (size, sender) = socket.receive_from().unwrap();
                let data = &socket.buffer[0..size];
                match MDNSPacket::try_from(data) {
                    Ok(packet) => {
                        _total += 1;
                        let is_unicast = packet.query_records.iter().any(|q| q.has_property);
                        if packet.query_records.iter().any(|q| q.label.contains("matter")) {
                            thread::sleep(Duration::from_millis(150));
                            if is_unicast {
                                socket.send_to(&packet_response, sender).unwrap();
                            } else {
                                socket.send_to(&packet_response, &mdns_dst).unwrap();
                            }
                            thread::sleep(Duration::from_millis(200));
                            // println!("Responding to both");
                        }
                    }
                    Err(_) => {
                        _failed += 1;
                    }
                }
                // print!("\rTotal: {}\tFailed {}", format!("{:5}", total), format!("{:5}", failed));
                stdout().flush().unwrap();
            }
        });
    }
}

pub fn start_advertising(udp_socket: &UdpSocket) {
    initialize_counter(&GLOBAL_UNENCRYPTED_COUNTER);
    let interface = netif::up().unwrap().find(|x| x.name() == "en0").unwrap();
    // let my_ip = "fdc3:de31:45b5:c843:14aa:95ef:2844:22e".to_string();
    let my_ip = "fdc3:de31:45b5:c843:89:981b:33af:57d2".to_string();
    let mac: [u8; 6] = [0xFF, 0x32, 0x11, 0x4, 0x2, 0x99];
    let mac_hex = hex::encode_upper(mac);
    let host_name = mac_hex.add(".local");
    let device_name = "thermostat.".to_string().add(PROTOCOL);

    MDNSService {
        udp_port: udp_socket.local_addr().unwrap().port(),
        ip: my_ip,
        host_name,
        device_name,
        discriminator: 300, // Still don't know how this is supposed to be computed.
        device_type: DeviceType::Thermostat,
        commission_state: CommissionState::NotCommissioned,
        vendor_id: 123,
        product_id: 456,
    }.start_advertising(&interface);
}