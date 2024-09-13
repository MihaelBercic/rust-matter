use crate::secure::enums::MatterDestinationID::Node;
use crate::secure::enums::MatterDestinationType::NodeID;
use crate::secure::enums::MatterSessionType::{Group, Unicast};
use crate::secure::message::MatterMessage;
use crate::secure::message_builder::MatterMessageBuilder;
use crate::secure::protocol::communication::counters::GLOBAL_UNENCRYPTED_COUNTER;
use crate::secure::protocol::enums::ProtocolOpcode;
use crate::secure::protocol::enums::ProtocolOpcode::PASEPake1;
use crate::secure::protocol::message::ProtocolMessage;
use crate::secure::protocol::message_builder::ProtocolMessageBuilder;
use crate::secure::protocol::secured_extensions::ProtocolSecuredExtensions;
use crate::utils::bit_subset::BitSubset;
use std::sync::atomic::Ordering;
use std::sync::mpsc::channel;
use std::thread;

#[test]
fn protocol_message_builder() {
    let message = ProtocolMessageBuilder::new()
        .set_opcode(ProtocolOpcode::PASEPake1)
        .set_is_sent_by_initiator(true)
        .set_acknowledged_message_counter(Some(GLOBAL_UNENCRYPTED_COUNTER.load(Ordering::Relaxed)).unwrap())
        .set_vendor(123)
        .set_secure_extensions(ProtocolSecuredExtensions { data_length: 0, data: vec![] })
        .set_payload("protocol_payload".as_bytes())
        .build();

    let bytes: Vec<u8> = message.to_bytes();
    let decoded_message = ProtocolMessage::try_from(&bytes[..]).unwrap();

    println!("{:?}", message);
    println!("{:?}", decoded_message);

    assert_eq!(message.opcode, PASEPake1);
    assert_eq!(message.exchange_flags.sent_by_initiator(), true);
    assert_eq!(message.exchange_flags.needs_acknowledgement(), false);
    assert_eq!(message.exchange_flags.is_acknowledgement(), true);
    assert_eq!(message.exchange_flags.is_vendor_present(), true);
    assert_eq!(message.protocol_vendor_id, Some(123));
    assert_eq!(message.exchange_flags.is_secured_extensions_present(), true);
    assert_eq!(message.payload, "protocol_payload".as_bytes());
    assert_ne!(message.payload, "matter_payload".as_bytes());
    assert_eq!(decoded_message, message);
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

    println!("{:?}", message);
    println!("{:?}", decoded_message);

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
