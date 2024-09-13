use crate::crypto::hash_message;
use crate::crypto::spake::SPAKE2P;
use crate::tlv::element_type::ElementType::*;
use crate::tlv::encodable_value::EncodableValue;
use crate::tlv::structs::pbkdf_param_request::PBKDFParamRequest;
use crate::tlv::tag_control::TagControl::{Anonymous0, CommonProfile16, CommonProfile32, ContextSpecific8, FullyQualified48, FullyQualified64};
use crate::tlv::tag_number::TagNumber::{Long, Medium, Short};
use crate::tlv::tlv::TLV;
use crate::tlv::{as_hex_string, create_advanced_tlv, create_tlv, parse_tlv, tlv_as_hex};
use std::io::Cursor;

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

#[test]
pub fn context_difference() {
    let a = "1530012040e26f0d08cca5cb58fc48e1c9d696495c08b97b04bfcfe8cc623e779a2c637625025e02240300280435052501f40125022c012503a00f24041124050b2606000003012407011818";
    let b = "1530012040e26f0d08cca5cb58fc48e1c9d696495c08b97b04bfcfe8cc623e779a2c637625025e02240300280435052601f401000026022c0100002503a00f1818";
    println!("{}", a);
    println!("{}", b);
    let a = hex::decode(a).unwrap();
    let b = hex::decode(b).unwrap();
    let tlv_a = TLV::try_from_cursor(&mut Cursor::new(&a)).unwrap();
    let tlv_b = TLV::try_from_cursor(&mut Cursor::new(&b)).unwrap();

    let p_a = PBKDFParamRequest::try_from(tlv_a).unwrap();
    let p_b = PBKDFParamRequest::try_from(tlv_b).unwrap();

    println!("{:?}", p_a);
    println!("{:?}", p_b);

    let tlv_a: TLV = p_a.into();
    let tlv_b: TLV = p_b.into();
    println!("{:?}", hex::encode(tlv_a.to_bytes()));
    println!("{:?}", hex::encode(tlv_b.to_bytes()));
}

#[test]
pub fn transcript_test() {
    let mut data = vec![];
    let p_a = hex::decode("04886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f5ff355163e43ce224e0b0e65ff02ac8e5c7be09419c785e0ca547d55a12e2d20").unwrap();
    let p_b = hex::decode("04d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b4907d60aa6bfade45008a636337f5168c64d9bd36034808cd564490b1e656edbe7").unwrap();
    data.extend_from_slice(&hex::decode("2000000000000000").unwrap());
    data.extend_from_slice(&hex::decode("d2405fa7622df1ac6d0a73ebdfc5c0563bea794175e5c95a4fb3c1f709be3151").unwrap());
    data.extend_from_slice(&hex::decode("0000000000000000").unwrap());
    data.extend_from_slice(&hex::decode("0000000000000000").unwrap());
    data.extend_from_slice(&hex::decode("4100000000000000").unwrap());
    data.extend_from_slice(&hex::decode("04886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f5ff355163e43ce224e0b0e65ff02ac8e5c7be09419c785e0ca547d55a12e2d20").unwrap());
    data.extend_from_slice(&hex::decode("4100000000000000").unwrap());
    data.extend_from_slice(&hex::decode("04d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b4907d60aa6bfade45008a636337f5168c64d9bd36034808cd564490b1e656edbe7").unwrap());
    data.extend_from_slice(&hex::decode("4100000000000000").unwrap());
    data.extend_from_slice(&hex::decode("0452126c0f56655ab7e0ade97a7c6fa2e3b091d0b1de50a5acfc6d888474e23b5a4af1e682a7c724e512d16b126d3bd155e87fded12987c36a8b2bcf022ff7a8c2").unwrap());
    data.extend_from_slice(&hex::decode("4100000000000000").unwrap());
    data.extend_from_slice(&hex::decode("047ef4872ada50b2779e3f956076a21e65c0843e116573ada208f6c5ca6d4a3b71f773168f9ec6b064d17985707a350725aae74da123989787ce4ba850db01090c").unwrap());
    data.extend_from_slice(&hex::decode("4100000000000000").unwrap());
    data.extend_from_slice(&hex::decode("04f5d1152952589ac3d4192bf8f719273c65f8a83a869a4637cc932469ad7eeb60a54cc47a203928bd0111c1285cc6f2a3daef3ad956f4a21a3323a5ee98f1dbb6").unwrap());
    data.extend_from_slice(&hex::decode("4100000000000000").unwrap());
    data.extend_from_slice(&hex::decode("0445eefcb926be981694dc7b29842313a049aa5907d154bdda684f0cc8d93a84d58633dfd34410a9aad6e43f9ebf60a872fa8a4c34f570a8eb7f151760dfb7e470").unwrap());
    data.extend_from_slice(&hex::decode("2000000000000000").unwrap());
    data.extend_from_slice(&hex::decode("93b315a1b86c6f0fb627feadde76c93cae8b6dc5e578951db04da543e1021aef").unwrap());
    println!("{:?}", hex::encode(hash_message(&data)));
    data.extend_from_slice(&hex::decode("2000000000000000").unwrap());
    data.extend_from_slice(&hex::decode("0f3ef80560e3a6bc0677a47d6ecd5bde62409d5b6e79cb7faaf0a20c584a4de8").unwrap());
    println!("{:?}", hex::encode(hash_message(&data)));

    let c = SPAKE2P::new().compute_confirmation(&data, &p_a, &p_b, 256);
    println!("cA = {:?}", hex::encode(c.cA));
    println!("cB = {:?}", hex::encode(c.cB));
    println!("Ke = {:?}", hex::encode(c.Ke));
}