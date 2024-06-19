use std::io::{stdout, Write};
use std::thread;
use std::time::Duration;

use netif::Interface;

use crate::constants::{MDNS_PORT, PROTOCOL};
use crate::discovery::enums::{CommissionState, DeviceType};
use crate::discovery::mdns::multicast_socket::MulticastSocket;
use crate::discovery::mdns::packet::MDNSPacket;
use crate::discovery::mdns::packet_header::MDNSPacketHeader;
use crate::discovery::mdns::records::{AAAARecord, PTRRecord, SRVRecord, TXTRecord};
use crate::discovery::mdns::records::complete_record::CompleteRecord;
use crate::discovery::mdns::records::record_information::RecordInformation;
use crate::discovery::mdns::records::record_type::RecordType;

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

        let mut total = 0usize;
        let mut failed = 0usize;
        let mdns_dst = format!("FF02::FB%{}:5353", &interface.name());
        thread::spawn(move || {
            loop {
                let (size, sender) = socket.receive_from().unwrap();
                let data = &socket.buffer[0..size];
                match MDNSPacket::try_from(data) {
                    Ok(packet) => {
                        total += 1;
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
                        failed += 1;
                    }
                }
                print!("\rTotal: {}\tFailed {}", format!("{:5}", total), format!("{:5}", failed));
                stdout().flush().unwrap();
            }
        });
    }
}