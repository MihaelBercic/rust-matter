use std::io::Cursor;

use crate::tlv::{as_hex_string, create_advanced_tlv, create_tlv, parse_tlv, tlv_as_hex};
use crate::tlv::element_type::ElementType::*;
use crate::tlv::encodable_value::EncodableValue;
use crate::tlv::tag_control::TagControl::{Anonymous0, CommonProfile16, CommonProfile32, ContextSpecific8, FullyQualified48, FullyQualified64};
use crate::tlv::tag_number::TagNumber::{Long, Medium, Short};
use crate::tlv::tlv::TLV;

///
/// @author Mihael Berčič
/// @date 1. 8. 24
#[test]
fn booleans() {
    assert_eq!(tlv_as_hex(Null), "14");    // Null             14
    assert_eq!(tlv_as_hex(BooleanFalse), "08");         // Boolean false    08
    assert_eq!(tlv_as_hex(BooleanTrue), "09");          // Boolean true     09
    // Reverse
    assert_eq!(as_hex_string(&TLV::try_from_cursor(&mut Cursor::new(&[0x14])).unwrap().to_bytes()), "14")
}

#[test]
fn signed_integers() {
    assert_eq!(tlv_as_hex(Signed8(42)), "00 2a");                                  // Signed Integer, 1-octet, value 42            00 2a
    assert_eq!(tlv_as_hex(Signed8(-17)), "00 ef");                                 // Signed Integer, 1-octet, value 42            00 ef
    assert_eq!(tlv_as_hex(Signed16(42)), "01 2a 00");                              // Signed Integer, 2-octet, value 42            01 2a 00
    assert_eq!(tlv_as_hex(Signed32(-170000)), "02 f0 67 fd ff");                   // Signed Integer, 4-octet, value -170000       02 f0 67 fd ff
    assert_eq!(tlv_as_hex(Signed64(40000000000)), "03 00 90 2f 50 09 00 00 00");   // Signed Integer, 8-octet, value 40000000000   03 00 90 2f 50 09 00 00 00
}

#[test]
fn unsigned_integers() {
    assert_eq!(tlv_as_hex(Unsigned8(42)), "04 2a");    // Unsigned Integer, 1-octet, value 42U     04 2a
    assert_eq!(tlv_as_hex(Unsigned8(42)), "04 2a");    // Unsigned Integer, 1-octet, value 42U     04 2a
}

#[test]
fn strings() {
    assert_eq!(tlv_as_hex(UTFString8("Hello!".to_string())), "0c 06 48 65 6c 6c 6f 21");       // UTF-8 String, 1-octet length, "Hello!"                   0c 06 48 65 6c 6c 6f 21
    assert_eq!(tlv_as_hex(UTFString8("Tschüs".to_string())), "0c 07 54 73 63 68 c3 bc 73");    // UTF-8 String, 1-octet length, "Tschüs"                   0c 07 54 73 63 68 c3 bc 73
    assert_eq!(tlv_as_hex(OctetString8(vec![00, 01, 02, 03, 04])), "10 05 00 01 02 03 04");    // Octet String, 1-octet length, octets [00 01 02 03 04]    10 05 00 01 02 03 04
}

#[test]
fn single_precision_floating_points() {
    assert_eq!(tlv_as_hex(FloatingPoint4(0.0)), "0a 00 00 00 00");                 // Single precision floating point 0.0                      0a 00 00 00 00
    assert_eq!(tlv_as_hex(FloatingPoint4(1.0 / 3.0)), "0a ab aa aa 3e");           // Single precision floating point (1.0 / 3.0)              0a ab aa aa 3e
    assert_eq!(tlv_as_hex(FloatingPoint4(17.9)), "0a 33 33 8f 41");                // Single precision floating point 17.9                     0a 33 33 8f 41
    assert_eq!(tlv_as_hex(FloatingPoint4(f32::INFINITY)), "0a 00 00 80 7f");       // Single precision floating point infinity (∞)             0a 00 00 80 7f
    assert_eq!(tlv_as_hex(FloatingPoint4(f32::NEG_INFINITY)), "0a 00 00 80 ff");   // Single precision floating point negative infinity (-∞)   0a 00 00 80 ff
}

#[test]
fn double_precision_floating_points() {
    assert_eq!(tlv_as_hex(FloatingPoint8(0.0)), "0b 00 00 00 00 00 00 00 00");               // Double precision floating point 0.0                      0b 00 00 00 00 00 00 00 00
    assert_eq!(tlv_as_hex(FloatingPoint8(1.0 / 3.0)), "0b 55 55 55 55 55 55 d5 3f");         // Double precision floating point (1.0 / 3.0)              0b 55 55 55 55 55 55 d5 3f
    assert_eq!(tlv_as_hex(FloatingPoint8(17.9)), "0b 66 66 66 66 66 e6 31 40");              // Double precision floating point 17.9                     0b 66 66 66 66 66 e6 31 40
    assert_eq!(tlv_as_hex(FloatingPoint8(f64::INFINITY)), "0b 00 00 00 00 00 00 f0 7f");     // Double precision floating point infinity (∞)             0b 00 00 00 00 00 00 f0 7f
    assert_eq!(tlv_as_hex(FloatingPoint8(f64::NEG_INFINITY)), "0b 00 00 00 00 00 00 f0 ff"); // Double precision floating point negative infinity (-∞)   0b 00 00 00 00 00 00 f0 ff
}


#[test]
fn tlv_samples() {}

#[test]
fn tlv_containers() {
    assert_eq!(tlv_as_hex(Structure(vec![])), "15 18");        // Empty Structure, {}    15 18
    assert_eq!(as_hex_string(&TLV::try_from_cursor(&mut Cursor::new(&[0x15, 0x18])).unwrap().to_bytes()), "15 18");

    assert_eq!(tlv_as_hex(Array(vec![])), "16 18");            // Empty Array, []        16 18
    assert_eq!(tlv_as_hex(List(vec![])), "17 18");             // Empty List, []         17 18

    /// Structure, two context specific tags, Signed Integer, 1 octet values, {0 = 42, 1 = -17}       15 20 00 2a 20 01 ef 18
    assert_eq!(tlv_as_hex(Structure(vec![
        create_advanced_tlv(Signed8(42), ContextSpecific8, Some(Short(0)), None, None),
        create_advanced_tlv(Signed8(-17), ContextSpecific8, Some(Short(1)), None, None),
    ])), "15 20 00 2a 20 01 ef 18");
    assert_eq!(
        as_hex_string(&TLV::try_from_cursor(&mut Cursor::new(&[0x15, 0x20, 0x00, 0x2a, 0x20, 0x01, 0xef, 0x18])).unwrap().to_bytes()),
        "15 20 00 2a 20 01 ef 18"
    );

    /// Array, Signed Integer, 1-octet values, [0, 1, 2, 3, 4]       16 00 00 00 01 00 02 00 03 00 04 18
    assert_eq!(tlv_as_hex(Array((0..=4i8).map(|i| create_advanced_tlv(Signed8(i), Anonymous0, None, None, None)).collect())), "16 00 00 00 01 00 02 00 03 00 04 18");
    assert_eq!(as_hex_string(&TLV::try_from_cursor(&mut Cursor::new(&[0x16, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x18])).unwrap().to_bytes()), "16 00 00 00 01 00 02 00 03 00 04 18");

    /// List, mix of anonymous and context tags, Signed Integer, 1 octet values, [[1, 0 = 42, 2, 3, 0 = -17]]   17 00 01 20 00 2a 00 02 00 03 20 00 ef 18
    assert_eq!(
        tlv_as_hex(List(vec![
            create_tlv(Signed8(1)),
            create_advanced_tlv(Signed8(42), ContextSpecific8, Some(Short(0)), None, None),
            create_tlv(Signed8(2)),
            create_tlv(Signed8(3)),
            create_advanced_tlv(Signed8(-17), ContextSpecific8, Some(Short(0)), None, None),
        ])), "17 00 01 20 00 2a 00 02 00 03 20 00 ef 18"
    );
    assert_eq!(as_hex_string(&TLV::try_from_cursor(&mut Cursor::new(&[0x17, 0x00, 0x01, 0x20, 0x00, 0x2a, 0x00, 0x02, 0x00, 0x03, 0x20, 0x00, 0xef, 0x18])).unwrap().to_bytes()), "17 00 01 20 00 2a 00 02 00 03 20 00 ef 18");


    /// Array, mix of element types, [42, -170000, {}, 17.9, "Hello!"]      16 00 2a 02 f0 67 fd ff 15 18 0a 33 33 8f 41 0c 06 48 65 6c 6c 6f 21 18
    assert_eq!(
        tlv_as_hex(Array(vec![
            create_tlv(Signed8(42)),
            create_tlv(Signed32(-170000)),
            create_tlv(Structure(vec![])),
            create_tlv(FloatingPoint4(17.9)),
            create_tlv(UTFString8("Hello!".to_string())),
        ])),
        "16 00 2a 02 f0 67 fd ff 15 18 0a 33 33 8f 41 0c 06 48 65 6c 6c 6f 21 18"
    );
    assert_eq!(as_hex_string(&TLV::try_from_cursor(&mut Cursor::new(&[0x16, 0x00, 0x2a, 0x02, 0xf0, 0x67, 0xfd, 0xff, 0x15, 0x18, 0x0a, 0x33, 0x33, 0x8f, 0x41, 0x0c, 0x06, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21, 0x18])).unwrap().to_bytes()), "16 00 2a 02 f0 67 fd ff 15 18 0a 33 33 8f 41 0c 06 48 65 6c 6c 6f 21 18");
}

#[test]
pub fn vendor() {
    assert_eq!(tlv_as_hex(Unsigned8(42)), "04 2a");
    assert_eq!(as_hex_string(&parse_tlv(&[0x04, 0x2a]).to_bytes()), "04 2a");

    assert_eq!(as_hex_string(&create_advanced_tlv(Unsigned8(42), ContextSpecific8, Some(Short(1)), None, None).to_bytes()), "24 01 2a");
    assert_eq!(as_hex_string(&parse_tlv(&[0x24, 0x01, 0x2a]).to_bytes()), "24 01 2a");

    assert_eq!(as_hex_string(&create_advanced_tlv(Unsigned8(42), CommonProfile16, Some(Medium(1)), None, None).to_bytes()), "44 01 00 2a");
    assert_eq!(as_hex_string(&parse_tlv(&[0x44, 0x01, 0x00, 0x2a]).to_bytes()), "44 01 00 2a");

    assert_eq!(as_hex_string(&create_advanced_tlv(Unsigned8(42), CommonProfile32, Some(Long(100000)), None, None).to_bytes()), "64 a0 86 01 00 2a");
    assert_eq!(as_hex_string(&parse_tlv(&[0x64, 0xa0, 0x86, 0x01, 0x00, 0x2a]).to_bytes()), "64 a0 86 01 00 2a");

    assert_eq!(as_hex_string(&create_advanced_tlv(Unsigned8(42), FullyQualified48, Some(Medium(1)), Some(0xFFF1), Some(0xDEED)).to_bytes()), "c4 f1 ff ed de 01 00 2a");
    assert_eq!(as_hex_string(&parse_tlv(&[0xc4, 0xf1, 0xff, 0xed, 0xde, 0x01, 0x00, 0x2a]).to_bytes()), "c4 f1 ff ed de 01 00 2a");

    assert_eq!(as_hex_string(&create_advanced_tlv(Unsigned8(42), FullyQualified64, Some(Long(0xAA55FEED)), Some(0xFFF1), Some(0xDEED)).to_bytes()), "e4 f1 ff ed de ed fe 55 aa 2a");
    assert_eq!(as_hex_string(&parse_tlv(&[0xe4, 0xf1, 0xff, 0xed, 0xde, 0xed, 0xfe, 0x55, 0xaa, 0x2a]).to_bytes()), "e4 f1 ff ed de ed fe 55 aa 2a");

    assert_eq!(as_hex_string(&create_advanced_tlv(Structure(vec![create_advanced_tlv(Unsigned8(42), FullyQualified48, Some(Medium(0xAA55)), Some(0xFFF1), Some(0xDEED))]), FullyQualified48, Some(Medium(1)), Some(0xFFF1), Some(0xDEED)).to_bytes()), "d5 f1 ff ed de 01 00 c4 f1 ff ed de 55 aa 2a 18");
    assert_eq!(as_hex_string(&parse_tlv(&[0xd5, 0xf1, 0xff, 0xed, 0xde, 0x01, 0x00, 0xc4, 0xf1, 0xff, 0xed, 0xde, 0x55, 0xaa, 0x2a, 0x18]).to_bytes()), "d5 f1 ff ed de 01 00 c4 f1 ff ed de 55 aa 2a 18");
}


