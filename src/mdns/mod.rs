use crate::crypto::random_bits;
use crate::mdns::constants::{IPV6_MULTICAST_ADDRESS, LOCAL_DOMAIN, MDNS_PORT};
use crate::mdns::device_information::DeviceInformation;
use crate::mdns::multicast_socket::MulticastSocket;
use crate::mdns::packet::MDNSPacket;
use crate::mdns::packet_header::MDNSPacketHeader;
use crate::mdns::records::complete_record::CompleteRecord;
use crate::mdns::records::record_information::RecordInformation;
use crate::mdns::records::record_type::RecordType;
use crate::mdns::records::record_type::RecordType::{AAAA, PTR, SRV, TXT};
use crate::mdns::records::{AAAARecord, PTRRecord, SRVRecord, TXTRecord};
use crate::session::counters::{
    initialize_counter, GLOBAL_GROUP_ENCRYPTED_CONTROL_MESSAGE_COUNTER, GLOBAL_GROUP_ENCRYPTED_DATA_MESSAGE_COUNTER, GLOBAL_UNENCRYPTED_COUNTER,
};
use crate::session::Device;
use crate::utils::StringExtensions;
use crate::{log_debug, log_error, log_info, NetworkInterface, SharedDevice};
use constants::{COMMISSIONED_PROTOCOL, NON_COMMISSIONED_PROTOCOL};
use enums::CommissionState;
use rand::Rng;
use std::io::Write;
use std::net::UdpSocket;
use std::ops::Add;
use std::thread;
use std::thread::sleep;
use std::time::Duration;
use verhoeff::VerhoeffMut;

pub(crate) mod constants;
pub mod device_information;
pub mod enums;
pub(crate) mod multicast_socket;
pub(crate) mod packet;
pub mod packet_header;
pub(crate) mod records;

/// Starts the mDNS-SD advertisement for our device.
pub fn start_advertising(udp: &UdpSocket, shared_device: SharedDevice, interface: &NetworkInterface) {
    initialize_counter(&GLOBAL_UNENCRYPTED_COUNTER);
    initialize_counter(&GLOBAL_GROUP_ENCRYPTED_DATA_MESSAGE_COUNTER);
    initialize_counter(&GLOBAL_GROUP_ENCRYPTED_CONTROL_MESSAGE_COUNTER);

    let mut _total = 0usize;
    let mut _failed = 0usize;
    let mdns_dst = format!("[{}%{}]:{}", IPV6_MULTICAST_ADDRESS, interface.index, MDNS_PORT);

    let device = shared_device.lock().unwrap();
    let information = &device.information;
    let mac = hex::encode_upper(&information.mac);
    let host_name = format!("{}.{}", mac, LOCAL_DOMAIN);
    let udp_port = udp.local_addr().unwrap().port();
    let mut socket = MulticastSocket::new(&interface, MDNS_PORT);

    log_debug!("Spawning a new multicast listening thread...");
    let shared_clone = shared_device.clone();
    thread::Builder::new()
        .name("Multicast listening".to_string())
        .stack_size(50 * 1024)
        .spawn(move || {
            loop {
                match socket.receive_from() {
                    Ok((size, sender)) => {
                        let data = &socket.buffer[0..size];
                        //TODO: Uncomment after stopped testing: if sender.ip() == ip { continue; }
                        match MDNSPacket::try_from(data) {
                            Ok(packet) => {
                                _total += 1;
                                let desired_queries: Vec<RecordInformation> = packet
                                    .query_records
                                    .iter()
                                    .filter(|x| {
                                        (x.label.contains(NON_COMMISSIONED_PROTOCOL)
                                            || x.label.contains(NON_COMMISSIONED_PROTOCOL)
                                            || x.label == host_name)
                                    })
                                    .map(|x| x.to_owned())
                                    .collect();
                                if desired_queries.is_empty() {
                                    continue;
                                }
                                let device = shared_clone.lock().unwrap();
                                let (is_unicast, packet_response) = build_response(&device, desired_queries, udp_port);
                                sleep(Duration::from_millis(150));
                                if is_unicast {
                                    socket.send(&packet_response, sender);
                                } else {
                                    socket.send(&packet_response, &mdns_dst);
                                }
                            }
                            Err(_) => {
                                _failed += 1;
                            }
                        }
                    }
                    Err(receive_error) => {
                        log_error!("Socket error: {}", receive_error);
                        sleep(Duration::from_secs(5));
                    }
                };
            }
        });
}

fn build_response(device: &Device, desired_queries: Vec<RecordInformation>, udp_port: u16) -> (bool, Vec<u8>) {
    let device = &device.information;

    let protocol = if device.commission_state == CommissionState::NotCommissioned {
        NON_COMMISSIONED_PROTOCOL
    } else {
        COMMISSIONED_PROTOCOL
    };

    let mac = hex::encode_upper(&device.mac);
    let host_name = format!("{}.{}", device.instance_name.clone(), LOCAL_DOMAIN);

    // let random: u64 = 0x705E698FD7D59D90;
    let instance_name = format!("{}.{}.{}", device.instance_name, protocol, LOCAL_DOMAIN);
    log_debug!("Instance name: {}", &instance_name);

    let domain_bytes: Vec<u8> = PTRRecord { domain: &instance_name }.into();

    let ptr_record = CompleteRecord {
        record_information: RecordInformation {
            label: format!("{}.{}", protocol, LOCAL_DOMAIN),
            record_type: RecordType::PTR,
            flags: 1,
            class_code: 1,
            has_property: true,
        },
        ttl: 30,
        data: domain_bytes.clone(),
    };
    let srv_record = CompleteRecord {
        record_information: RecordInformation {
            label: instance_name.to_string(),
            record_type: RecordType::SRV,
            flags: 0,
            class_code: 1,
            has_property: true,
        },
        ttl: 30,
        data: SRVRecord {
            target: host_name.to_string(),
            priority: 0,
            weight: 0,
            port: udp_port,
        }
        .into(),
    };
    let aaaa_record = CompleteRecord {
        record_information: RecordInformation {
            label: host_name.to_string(),
            record_type: RecordType::AAAA,
            flags: 0,
            class_code: 1,
            has_property: true,
        },
        ttl: 30,
        data: AAAARecord {
            address: device.ip.to_string(),
        }
        .into(),
    };

    let sub_l_record = CompleteRecord {
        record_information: RecordInformation {
            label: format!("_L{}._sub.{}.{}", device.discriminator, protocol, LOCAL_DOMAIN),
            record_type: PTR,
            flags: 1,
            class_code: 1,
            has_property: true,
        },
        ttl: 30,
        data: domain_bytes.clone(),
    };
    let sub_s_record = CompleteRecord {
        record_information: RecordInformation {
            label: format!("_S{}._sub.{}.{}", device.discriminator >> 8, protocol, LOCAL_DOMAIN),
            record_type: PTR,
            flags: 1,
            class_code: 1,
            has_property: true,
        },
        ttl: 30,
        data: domain_bytes.clone(),
    };
    let sub_t_record = CompleteRecord {
        record_information: RecordInformation {
            label: format!("_T{}._sub.{}.{}", device.device_type as u16, protocol, LOCAL_DOMAIN),
            record_type: PTR,
            flags: 1,
            class_code: 1,
            has_property: true,
        },
        ttl: 30,
        data: domain_bytes.clone(),
    };
    let sub_cm_record = CompleteRecord {
        record_information: RecordInformation {
            label: format!("_CM._sub.{}.{}", protocol, LOCAL_DOMAIN),
            record_type: PTR,
            flags: 1,
            class_code: 1,
            has_property: true,
        },
        ttl: 30,
        data: domain_bytes.clone(),
    };

    log_debug!("IPv6: {}", device.ip.to_string());

    let txt_record = CompleteRecord {
        record_information: RecordInformation {
            label: instance_name.clone(),
            record_type: RecordType::TXT,
            flags: 0,
            class_code: 1,
            has_property: true,
        },
        ttl: 30,
        data: TXTRecord {
            pairs: vec![
                ("D", device.discriminator.to_string()),
                ("CM", (device.commission_state as u8).to_string()),
                ("DT", (device.device_type as u16).to_string()),
                ("DN", device.device_name.clone()),
                ("PH", "1".to_string()),
                ("VP", format!("{}+{}", device.vendor_id, device.product_id)),
            ],
        }
        .into(),
    };

    let mut query_iterator = desired_queries.iter();
    let include_pointer = query_iterator.any(|x| x.record_type == PTR);
    let include_txt = query_iterator.any(|r| r.record_type == TXT);
    let include_srv = query_iterator.any(|r| r.record_type == SRV);
    let include_aaaa = query_iterator.any(|r| r.record_type == AAAA);
    let is_unicast = query_iterator.any(|q| q.has_property);

    let mut answer_records: Vec<CompleteRecord> = vec![];
    let mut additional_records: Vec<CompleteRecord> = vec![];
    if include_pointer {
        answer_records.push(ptr_record.clone());
        additional_records.extend_from_slice(&[
            txt_record.clone(),
            aaaa_record.clone(),
            srv_record.clone(),
            sub_l_record.clone(),
            sub_cm_record.clone(),
            sub_s_record.clone(),
            sub_t_record.clone(),
        ]);
    }
    if include_txt {
        answer_records.push(txt_record.clone())
    }
    if include_srv {
        answer_records.push(srv_record.clone())
    }
    if include_aaaa {
        answer_records.push(aaaa_record.clone())
    }

    let packet_response: Vec<u8> = MDNSPacket {
        header: MDNSPacketHeader::new_with_flags(0, true, 0, false, false),
        query_records: desired_queries,
        answer_records,
        additional_records,
        authority_records: vec![],
    }
    .into();
    (is_unicast, packet_response)
}
