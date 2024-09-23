use crate::session::counters::GLOBAL_UNENCRYPTED_COUNTER;
use crate::session::matter::builder::MatterMessageBuilder;
use crate::session::matter::enums::MatterDestinationID::Node;
use crate::session::matter::enums::MatterDestinationType::NodeID;
use crate::session::matter::enums::MatterSessionType::{Group, Unicast};
use crate::session::matter_message::MatterMessage;
use crate::session::protocol::enums::SecureChannelProtocolOpcode::PASEPake1;
use crate::session::protocol::message_builder::ProtocolMessageBuilder;
use crate::session::protocol::secured_extensions::ProtocolSecuredExtensions;
use crate::utils::bit_subset::BitSubset;
use std::net::UdpSocket;
use std::sync::atomic::Ordering;
use std::sync::mpsc::channel;
use std::thread;

#[test]
fn protocol_message_builder() {
    let message = ProtocolMessageBuilder::new()
        .set_opcode(PASEPake1 as u8)
        .set_is_sent_by_initiator(true)
        .set_acknowledged_message_counter(Some(GLOBAL_UNENCRYPTED_COUNTER.load(Ordering::Relaxed)).unwrap())
        .set_vendor(123)
        .set_secure_extensions(ProtocolSecuredExtensions { data_length: 0, data: vec![] })
        .set_payload("protocol_payload".as_bytes())
        .build();

    assert_eq!(message.opcode, PASEPake1 as u8);
    assert_eq!(message.exchange_flags.sent_by_initiator(), true);
    assert_eq!(message.exchange_flags.needs_acknowledgement(), false);
    assert_eq!(message.exchange_flags.is_acknowledgement(), true);
    assert_eq!(message.exchange_flags.is_vendor_present(), true);
    assert_eq!(message.protocol_vendor_id, Some(123));
    assert_eq!(message.exchange_flags.is_secured_extensions_present(), true);
    assert_eq!(message.payload, "protocol_payload".as_bytes());
    assert_ne!(message.payload, "matter_payload".as_bytes());

    // let bytes: Vec<u8> = message.to_bytes();
    // let decoded_message = ProtocolMessage::try_from(&bytes[..]).unwrap();
    // assert_eq!(decoded_message, message);
}

#[test]
fn matter_message_builder() {
    let message_builder = MatterMessageBuilder::new();
    let message = message_builder
        .set_version(1)
        .set_session_type(Group)
        .set_privacy_encoded(true)
        .set_destination(Node(15))
        .set_session_type(Unicast)
        .set_payload("hello".as_bytes())
        .build();
    let bytes = message.as_bytes();
    let decoded_message = MatterMessage::try_from(&bytes[..]).unwrap();

    assert_eq!(decoded_message, message);
    assert_eq!(message.header.flags.version(), 1);
    assert_eq!(message.header.security_flags.session_type(), Unicast);
    assert_eq!(message.header.security_flags.is_encoded_with_privacy(), true);
    assert_eq!(message.header.destination_node_id.unwrap(), Node(15));
    assert_eq!(message.header.flags.type_of_destination(), Some(NodeID));
    assert_eq!(message.payload, "hello".as_bytes());
    assert_ne!(bytes.len(), 0);
}

#[test]
fn set_bits() {
    let mut x = 1u8;
    x.set_bits(0..=2, 0b11);
    assert_eq!(x, 0b0000_0011);
    x.set_bits(0..=1, 0b0);
    assert_eq!(x, 0b0000_0000);
    x.set_bits(3..=7, 0b10101);
    assert_eq!(x, 0b1010_1000);
    x = u8::MAX;
    x.set_bits(0..=4, 0b00110);
    assert_eq!(x, 0b1110_0110);
    x = u8::MAX;
    x.set_bits(0..=0, 0);
    assert_eq!(x, 0b1111_1110);
    x = 0;
    x.set_bits(3..=3, 1);
    assert_eq!(x, 0b0000_1000);
    x = 0;
    x.set_bits(3..=5, 0b111);
    assert_eq!(x, 0b0011_1000);

    x = 0;
    x.set_bits(4..=5, 0b11);
    assert_eq!(x, 0b0011_0000);
}

#[test]
fn queue_test() {
    let (tx, rx) = channel::<u8>();
    thread::spawn(move || {
        let sender = tx.clone();
        for i in 0..5 {
            let _ = sender.send(i);
        }
    });

    thread::spawn(move || {
        let mut total_received = 0;
        while total_received < 5 {
            match rx.recv() {
                Ok(id) => {
                    assert_eq!(total_received, id);
                    total_received += 1;
                }
                Err(error) => { panic!("{:#?}", error) }
            }
        }
        assert_eq!(total_received, 5);
    }).join().expect("Unable to join the thread...");
}


#[test]
pub fn udp_sample() {
    let udp = UdpSocket::bind("[::]:0").unwrap();
    let data = hex::decode("01000000b952220d482791e3cee6d33506235779000002f77a0815300120b2a23f80877b3b3dd3aa1b32464da363718637c0aa295ad6543718355a95a582300220b06fc28a6f644e2dd790129f293e546c61b6905e70c5794afd2d6b5850d1bf002503836535042501e803300220000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f1835052601f401000026022c0100002503a00f1818").unwrap();
    udp.send_to(&data, udp.local_addr().unwrap()).unwrap();
}