#[cfg(test)]
pub mod discovery_tests {
    use std::net::TcpListener;
    use std::ops::Add;

    use crate::discovery::constants::{ADD_ACCESSORY_PACKET, PROTOCOL};
    use crate::discovery::mdns::records::aaaa_record::AAAARecord;
    use crate::discovery::mdns::records::ptr_record::PTRRecord;
    use crate::discovery::mdns::records::srv_record::SRVRecord;
    use crate::discovery::mdns::structs::{BitSubset, CompleteRecord, MDNSPacket, MDNSPacketHeader, RecordInformation, RecordType};

    #[test]
    fn hello() {
        // println!("{}", String::from_utf8_lossy(&SAMPLE_PACKET));
        let mdns_packet = MDNSPacket::from(&ADD_ACCESSORY_PACKET[..]);
        let is_our_protocol = mdns_packet.query_records.iter().any(|q| q.label == PROTOCOL);
        println!("Is our protocol: {}", is_our_protocol);
    }

    #[test]
    fn packet_builder() {
        let mac: [u8; 6] = [0xFF, 0x32, 0x11, 0x4, 0x2, 0x99];
        let mac_hex = hex::encode_upper(mac);
        let host_name = mac_hex.add(".local");
        let device_name = "thermostat".to_string().add(PROTOCOL);
        let tcp_socket = TcpListener::bind("[::]:0").expect("Unable to bind to tcp...");
        println!("{}", host_name);

        let mut buffer: Vec<u8> = vec![];
        //     private val srvRecord = SRVRecord(recordName, targetName, settings.port, timeToLive = 4500, isCached = false)
        let ptr_record = CompleteRecord {
            record_information: RecordInformation {
                label: PROTOCOL.to_string(),
                record_type: RecordType::PTR,
                flags: 1,
                class_code: 0,
                has_property: false,
            },
            ttl: 4400,
            data: PTRRecord { domain: device_name.clone() }.into(),
        };
        let srv_record = CompleteRecord {
            record_information: RecordInformation {
                label: device_name,
                record_type: RecordType::SRV,
                flags: 0,
                class_code: 0,
                has_property: false,
            },
            ttl: 4400,
            data: SRVRecord {
                target: host_name.clone(),
                priority: 0,
                weight: 0,
                port: tcp_socket.local_addr().unwrap().port(),
            }.into(),
        };
        let aaaa_record = CompleteRecord {
            record_information: RecordInformation {
                label: host_name,
                record_type: RecordType::AAAA,
                flags: 0,
                class_code: 0,
                has_property: false,
            },
            ttl: 4400,
            data: AAAARecord { address: "fdc3:de31:45b5:c843:14aa:95ef:2844:22e".to_string() }.into(),
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
            additional_records: vec![srv_record, aaaa_record],
            authority_records: vec![],
        };


        let buffer: Vec<u8> = my_packet.into();
        let as_binary: Vec<String> = buffer.iter().map(|b| format!("{:08b}", b)).collect();
        println!("{}", as_binary.join(" "));
        println!("{}", String::from_utf8_lossy(&buffer));
    }

    #[test]
    fn bit_subset() {
        let num = 0xFF; // 1111 1111 = 255
        let desired = 0xF; // 1111 = 15;
        assert_eq!(num.bit_subset(4, 4), desired);
    }
}
