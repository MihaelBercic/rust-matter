use crate::constants::{TEST_CMS_SIGNER_PRIVATE_KEY, TEST_CMS_SIGNER_SUBJECT_KEY_IDENTIFIER};
use crate::crypto::constants::{CRYPTO_GROUP_SIZE_BYTES, CRYPTO_HASH_LEN_BYTES};
use crate::mdns::enums::DeviceType;
use crate::mdns::enums::DeviceType::Light;
use crate::session::protocol::interaction::cluster::operational_credentials::{CertificationDeclaration, DerCertificationDeclaration, DigestAlgorithmIdentifier, EncapsulatedContentInfo, Pkcs7SignedData, SignerInfo};
use crate::tlv::tlv::TLV;
use block_padding::Padding;
use der::asn1::{ContextSpecific, Int, OctetString, SetOf};
use der::TagMode::Implicit;
use der::{Encode, TagMode, TagNumber};
use hmac::digest::MacError;
use hmac::{Hmac, Mac};
use p256::ecdh::EphemeralSecret;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::signature::{SignatureEncoding, Signer};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::elliptic_curve::rand_core::OsRng;
use p256::PublicKey;
use rand::{thread_rng, Rng};
use sha2::{Digest, Sha256};
use std::str::FromStr;

pub mod constants;
pub mod kdf;
pub mod spake;
pub mod symmetric;

type HmacSha256 = Hmac<Sha256>;

pub struct KeyPair {
    pub private_key: SigningKey,
    pub public_key: VerifyingKey,
}

pub struct EccKeyPair {
    pub private_key: EphemeralSecret,
    pub public_key: PublicKey,
}

/// Uses SHA-256 to hash the provided message.
pub fn hash_message(message: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(message);
    let result = hasher.finalize();
    let mut output_data: [u8; 32] = [0; 32];
    output_data.copy_from_slice(&result[..]);
    output_data
}

/// Generates a hash of the [message] with the provided [key];
pub fn hmac(key: &[u8], message: &[u8]) -> [u8; CRYPTO_HASH_LEN_BYTES] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC takes any key size");
    mac.update(message);
    let result = mac.finalize();
    result.into_bytes().try_into().unwrap()
}

/// Verifies HMAC hash using the [key], [message] and [hashed message](code_bytes);
pub fn verify_hmac(key: &[u8], message: &[u8], code_bytes: &[u8]) -> Result<(), MacError> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC should take any key size");
    mac.update(message);
    mac.verify_slice(&code_bytes[..])
}

/// ECDSA - Generates a Public - Private key pair using NIST-P256
pub fn generate_key_pair() -> KeyPair {
    let private_key = SigningKey::random(&mut OsRng);
    let public_key = VerifyingKey::from(&private_key);
    KeyPair {
        private_key,
        public_key,
    }
}

/// ECDH - Generates a Public - Private key pair using NIST-P256
pub fn ecc_generate_key_pair() -> EccKeyPair {
    let private_key = EphemeralSecret::random(&mut OsRng);
    let public_key = private_key.public_key();
    EccKeyPair {
        private_key,
        public_key,
    }
}

/// Signs a message using the [key] into signature which is of length [2 * CRYPTO_GROUP_SIZE_BYTES]
/// TODO: Check in case of BigEndian errors
pub fn sign_message(key: &SigningKey, message: &[u8]) -> [u8; 2 * CRYPTO_GROUP_SIZE_BYTES] {
    let signed: Signature = key.sign(message);
    let mut signature_bytes = [0u8; 2 * CRYPTO_GROUP_SIZE_BYTES];
    signature_bytes.copy_from_slice(&signed.to_bytes()[..]);
    signature_bytes
}

/// Signs a message using the [key] into signature which is of length [2 * CRYPTO_GROUP_SIZE_BYTES]
/// TODO: Check in case of BigEndian errors
pub fn sign_message_with_signature(key: &SigningKey, message: &[u8]) -> Signature {
    key.sign(message)
}

/// Computes ECDH shared secret using [ecdh]
pub fn ecdh(private_key: EphemeralSecret, public_key: &[u8]) -> [u8; CRYPTO_GROUP_SIZE_BYTES] {
    let their_public = PublicKey::from_sec1_bytes(public_key).expect("Invalid public key.");
    let shared = private_key.diffie_hellman(&their_public);
    let mut bytes = [0u8; CRYPTO_GROUP_SIZE_BYTES];
    bytes.copy_from_slice(&shared.raw_secret_bytes()[..]);
    bytes
}

/// Computes [N] random bytes and stores them in a vector.
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut array = [0u8; N];
    let mut rng = thread_rng();
    for i in 0..N {
        array[i] = rng.gen_range(0..255)
    }
    array
}

/// Compute random [len] bits.
pub fn random_bits(len: usize) -> Vec<u8> {
    let mut rng = thread_rng();
    let mut bytes: Vec<u8> = vec![];
    let mut current = 0u8;
    for i in 1..=len {
        current |= if rng.gen_bool(0.5) { 1 } else { 0 };
        if i % 8 == 0 || i == len {
            bytes.insert(0, current);
            current = 0;
        } else {
            current <<= 1;
        }
    }
    bytes
}


#[cfg(test)]
#[test]
pub fn csa_asn() {
    let input = CertificationDeclaration {
        format_version: 1,
        vendor_id: 0xFFF1,
        product_id: vec![0x8000],
        device_type_id: 0x1234,
        certificate_id: "ZIG20141ZB330001-24".to_string(),
        security_level: 0,
        security_information: 0,
        version_number: 0x2694,
        certification_type: 0,
        dac_origin_vendor_id: None,
        dac_origin_product_id: None,
    };
    let tlv: TLV = TLV::simple(input.into());
    assert_eq!(hex::encode(tlv.clone().to_bytes()), "152400012501f1ff360205008018250334122c04135a494732303134315a423333303030312d32342405002406002507942624080018");

    let x = "3081e806092a864886f70d010702a081da3081d7020103310d300b0609608648016503040201304506092a864886f70d010701a0380436152400012501f1ff360205008018250334122c04135a494732303134315a423333303030312d32342405002406002507942624080018317c307a020103801462fa823359acfaa9963e1cfa140addf504f37160300b0609608648016503040201300a06082a8648ce3d0403020446304402204308c3e5b86733243b1db4e930607b09a83d6e1beec7e0598e541c05f3d2b64602205479cd937810bb0f2311348984e6541ecc5c15661256ef93244f8b9b985fb04e";

    let signing_key: SigningKey = SigningKey::from_slice(&hex::decode(TEST_CMS_SIGNER_PRIVATE_KEY).unwrap()).unwrap();
    let signature: Signature = signing_key.sign(&tlv.clone().to_bytes());
    let der_signature = signature.clone().to_der().to_vec();

    let sample = DerCertificationDeclaration {
        version: Int::new(&[3]).unwrap(),
        digest_algorithm: SetOf::try_from([
            DigestAlgorithmIdentifier { algorithm: "2.16.840.1.101.3.4.2.1".parse().unwrap() }
        ]).unwrap(),
        encapsulated_content: EncapsulatedContentInfo {
            content_type: "1.2.840.113549.1.7.1".parse().unwrap(),
            content: ContextSpecific {
                tag_number: TagNumber::new(0),
                tag_mode: Default::default(),
                value: OctetString::new(tlv.clone().to_bytes()).unwrap(),
            },
        },
        signer_info: SetOf::try_from([
            SignerInfo {
                version: Int::new(&[3]).unwrap(),
                subject_key_identifier: ContextSpecific {
                    tag_number: TagNumber::new(0),
                    tag_mode: Implicit,
                    value: OctetString::new(hex::decode(TEST_CMS_SIGNER_SUBJECT_KEY_IDENTIFIER).unwrap()).unwrap(),
                },
                digest_algorithm: DigestAlgorithmIdentifier { algorithm: "2.16.840.1.101.3.4.2.1".parse().unwrap() },
                signature_algorithm: DigestAlgorithmIdentifier {
                    algorithm: "1.2.840.10045.4.3.2".parse().unwrap()
                },
                signature: OctetString::new(der_signature).unwrap(),
            }
        ]).unwrap(),
    };

    let pkcs = Pkcs7SignedData {
        algorithm: "1.2.840.113549.1.7.2".parse().unwrap(),
        value: ContextSpecific {
            tag_number: TagNumber::new(0),
            tag_mode: TagMode::Explicit,
            value: sample,
        },
    };
    let encoded = pkcs.to_der().unwrap();
    // let encoded = EncapsulatedContentInfo {
    //     content_type: "1.2.840.113549.1.7.1".parse().unwrap(),
    //     content: OctetString::new(tlv.clone().to_bytes()).unwrap(),
    // }.to_der().unwrap();

    // println!("{:?}", hex::encode(&encoded));
    let desired = "3081e806092a864886f70d010702a081da3081d7020103310d300b0609608648016503040201304506092a864886f70d010701a0380436152400012501f1ff360205008018250334122c04135a494732303134315a423333303030312d32342405002406002507942624080018317c307a020103801462fa823359acfaa9963e1cfa140addf504f37160300b0609608648016503040201300a06082a8648ce3d04030204463044022043a63f2b943df33c38b3e02fcaa75fe3532aebbf5e63f5bbdbc0b1f01d3c4f6002204c1abf5f1807b81894b1576c47e4724e4d966c612ed3fa25c118c3f2b3f90369";
    let desired = hex::decode(desired).unwrap();
    // assert_eq!(x, hex::encode(&encoded));

    compute_certificate(0x8000, Light);
    // assert_eq!(encoded, desired);

    /*
    30 81 e8 06 09 2a 86 48 86 f7 0d 01 07 02 a0 81
    da 30 81 d7 02 01 03 31 0d 30 0b 06 09 60 86 48
    01 65 03 04 02 01 30 45 06 09 2a 86 48 86 f7 0d
    01 07 01 a0 38 04 36 15 24 00 01 25 01 f1 ff 36
    02 05 00 80 18 25 03 34 12 2c 04 13 5a 49 47 32
    30 31 34 31 5a 42 33 33 30 30 30 31 2d 32 34 24
    05 00 24 06 00 25 07 94 26 24 08 00 18 31 7c 30
    7a 02 01 03 80 14 62 fa 82 33 59 ac fa a9 96 3e 
    1c fa 14 0a dd f5 04 f3 71 60 30 0b 06 09 60 86
    48 01 65 03 04 02 01 30 0a 06 08 2a 86 48 ce 3d
    04 03 02 04 46 30 44 02 20 43 a6 3f 2b 94 3d f3
    3c 38 b3 e0 2f ca a7 5f e3 53 2a eb bf 5e 63 f5
    bb db c0 b1 f0 1d 3c 4f 60 02 20 4c 1a bf 5f 18
    07 b8 18 94 b1 57 6c 47 e4 72 4e 4d 96 6c 61 2e
    d3 fa 25 c1 18 c3 f2 b3 f9 03 69
     */
}

pub fn compute_certificate(product_id: u16, device_type: DeviceType) -> Vec<u8> {
    let input = CertificationDeclaration {
        format_version: 3,
        vendor_id: 0xFFF1,
        product_id: vec![product_id],
        device_type_id: 22, //device_type as u32,
        certificate_id: "CSA00000SWC00000-00".to_string(),
        security_level: 0,
        security_information: 0,
        version_number: 1,
        certification_type: 0,
        dac_origin_vendor_id: None,
        dac_origin_product_id: None,
    };
    let tlv: TLV = TLV::simple(input.into());
    let signing_key: SigningKey = SigningKey::from_slice(&hex::decode(TEST_CMS_SIGNER_PRIVATE_KEY).unwrap()).unwrap();
    let signature: Signature = signing_key.sign(&tlv.clone().to_bytes());
    let der_signature = signature.clone().to_der().to_vec();

    let sample = DerCertificationDeclaration {
        version: Int::new(&[3]).unwrap(),
        digest_algorithm: SetOf::try_from([
            DigestAlgorithmIdentifier { algorithm: "2.16.840.1.101.3.4.2.1".parse().unwrap() }
        ]).unwrap(),
        encapsulated_content: EncapsulatedContentInfo {
            content_type: "1.2.840.113549.1.7.1".parse().unwrap(),
            content: ContextSpecific {
                tag_number: TagNumber::new(0),
                tag_mode: Default::default(),
                value: OctetString::new(tlv.clone().to_bytes()).unwrap(),
            },
        },
        signer_info: SetOf::try_from([
            SignerInfo {
                version: Int::new(&[3]).unwrap(),
                subject_key_identifier: ContextSpecific {
                    tag_number: TagNumber::new(0),
                    tag_mode: Implicit,
                    value: OctetString::new(hex::decode(TEST_CMS_SIGNER_SUBJECT_KEY_IDENTIFIER).unwrap()).unwrap(),
                },
                digest_algorithm: DigestAlgorithmIdentifier { algorithm: "2.16.840.1.101.3.4.2.1".parse().unwrap() },
                signature_algorithm: DigestAlgorithmIdentifier {
                    algorithm: "1.2.840.10045.4.3.2".parse().unwrap()
                },
                signature: OctetString::new(der_signature).unwrap(),
            }
        ]).unwrap(),
    };

    let pkcs = Pkcs7SignedData {
        algorithm: "1.2.840.113549.1.7.2".parse().unwrap(),
        value: ContextSpecific {
            tag_number: TagNumber::new(0),
            tag_mode: TagMode::Explicit,
            value: sample,
        },
    };
    let encoded = pkcs.to_der().unwrap();
    println!("{}", hex::encode(&encoded));
    encoded
}