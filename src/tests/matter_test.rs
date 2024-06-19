use crate::Matter;
use crate::service::protocol::message_builder::ProtocolMessageBuilder;
use crate::service::protocol::secured_extensions::ProtocolSecuredExtensions;
use crate::utils::bit_subset::BitSubset;

#[test]
fn matter_setup() {
    let _matter = Matter::new();

    // let matter_service = MatterService::new();
    // matter_service.process(matter_message);
}

#[test]
fn protocol_message_builder() {
    let message = ProtocolMessageBuilder::new()
        .set_opcode(10)
        .set_is_sent_by_initiator(true)
        .set_needs_acknowledgement(true)
        .set_vendor(123)
        .set_secure_extensions(ProtocolSecuredExtensions {
            data_length: 0,
            data: vec![],
        })
        .build();

    assert_eq!(message.opcode, 10);
    assert_eq!(message.exchange_flags.sent_by_initiator(), true);
    assert_eq!(message.exchange_flags.needs_acknowledgement(), true);
    assert_eq!(message.exchange_flags.is_vendor_present(), true);
    assert_eq!(message.protocol_vendor_id, Some(123));
    assert_eq!(message.exchange_flags.is_secured_extensions_present(), true);
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
}