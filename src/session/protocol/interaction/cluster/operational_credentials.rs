use crate::constants::TEST_CERT_PAA_NO_VID_CERT;
use crate::crypto::compute_certificate;
use crate::mdns::enums::DeviceType::Thermostat;
use crate::session::protocol::interaction::cluster::operational_credentials::CertificateChainType::PAI;
use crate::session::protocol::interaction::cluster::ClusterImplementation;
use crate::session::protocol::interaction::enums::QueryParameter;
use crate::session::protocol::interaction::enums::QueryParameter::Specific;
use crate::session::protocol::interaction::information_blocks::attribute::report::AttributeReport;
use crate::session::protocol::interaction::information_blocks::attribute::Attribute;
use crate::session::protocol::interaction::information_blocks::{AttributePath, CommandData, CommandPath, InvokeResponse};
use crate::session::session::Session;
use crate::tlv::element_type::ElementType;
use crate::tlv::element_type::ElementType::{Array, Structure};
use crate::tlv::tag::Tag;
use crate::tlv::tag_control::TagControl::ContextSpecific8;
use crate::tlv::tag_number::TagNumber::Short;
use crate::tlv::tlv::TLV;
use crate::{crypto, log_info, START_TIME};
use der::asn1::{ContextSpecific, ObjectIdentifier, OctetString, SetOf};
use der::{Encode, Sequence, ValueOrd};
use sec1::DecodeEcPrivateKey;
use std::any::Any;

///
/// @author Mihael Berčič
/// @date 8. 10. 24
///
const RESP_MAX_BYTES: usize = 900;

/// `nocs` List of all Node Operational Certificates.
///
/// `fabrics` List of all fabrics of the node.
///
/// `supported_fabrics`: Number of fabrics the device can support \[5,254\];
///
/// `commissioned_fabrics`: Current count of commissioned fabrics.
///
/// `trusted_root_certificates`: A list of all trusted root certificates (octet strings).
///
/// `current_fabric_index`: The current fabric index.
pub struct OperationalCredentialsCluster {
    pub nocs: Attribute<Vec<NOC>>,
    pub fabrics: Attribute<Vec<FabricDescriptor>>,
    pub supported_fabrics: Attribute<u8>,
    pub commissioned_fabrics: Attribute<u8>,
    pub trusted_root_certificates: Attribute<Vec<Vec<u8>>>,
    pub current_fabric_index: Attribute<u8>,
}

impl OperationalCredentialsCluster {
    pub fn new() -> Self {
        Self {
            nocs: Default::default(),
            fabrics: Default::default(),
            supported_fabrics: Default::default(),
            commissioned_fabrics: Default::default(),
            trusted_root_certificates: Default::default(),
            current_fabric_index: Default::default(),
        }
    }

    fn attestation_request(&mut self, data: Option<TLV>, session: &mut Session) -> Vec<InvokeResponse> {
        let data = data.unwrap();
        let Structure(children) = data.control.element_type else {
            panic!("Yeah incorrect data...");
        };
        let nonce = children.first().unwrap().to_owned().control.element_type.into_octet_string().unwrap();

        let der = compute_certificate(0x8000, Thermostat);
        let attestation_elements = TLV::simple(Structure(vec![
            TLV::new(der.clone().into(), ContextSpecific8, Tag::simple(Short(1))),
            TLV::new(nonce.into(), ContextSpecific8, Tag::simple(Short(2))),
            TLV::new((START_TIME.elapsed().unwrap().as_secs() as u32).into(), ContextSpecific8, Tag::simple(Short(3))),
        ])).to_bytes();


        let mut tbs = attestation_elements.clone();
        tbs.extend_from_slice(&session.attestation_challenge);


        let key = ecdsa::SigningKey::from_sec1_der(&der[..]).unwrap();
        let signature = crypto::sign_message(&key, &tbs);

        vec![
            InvokeResponse {
                command: Some(CommandData {
                    path: CommandPath::new(Specific(0x01)),
                    fields: Some(
                        TLV::simple(Structure(vec![
                            TLV::new(attestation_elements.into(), ContextSpecific8, Tag::simple(Short(0))),
                            TLV::new(signature.to_vec().into(), ContextSpecific8, Tag::simple(Short(1))),
                        ]))
                    ),
                }),
                status: None,
            }
        ]
    }
    fn certificate_chain_request(&mut self, data: Option<TLV>) -> Vec<InvokeResponse> {
        if let Some(tlv) = data {
            if let Structure(data) = tlv.control.element_type {
                for child in data {
                    let chain_type = child.control.element_type.into_u8().unwrap();
                    let chain_type = if chain_type == 1 { CertificateChainType::DAC } else { PAI };
                    log_info!("Working with certificate type: {:?}", chain_type);
                }
            }
        }
        vec![
            InvokeResponse {
                command: Some(CommandData {
                    path: CommandPath::new(Specific(0x03)),
                    fields: Some(TLV::simple(Structure(vec![
                        TLV::new(hex::decode(TEST_CERT_PAA_NO_VID_CERT).unwrap().into(), ContextSpecific8, Tag::simple(Short(0))),
                    ]))),
                }),
                status: None,
            }
        ]
    }
    fn csr_request(&mut self, data: Option<TLV>) -> Vec<InvokeResponse> { todo!() }
    fn add_noc(&mut self, data: Option<TLV>) -> Vec<InvokeResponse> { todo!() }
    fn update_noc(&mut self, data: Option<TLV>) -> Vec<InvokeResponse> { todo!() }
    fn update_fabric_label(&mut self, data: Option<TLV>) -> Vec<InvokeResponse> { todo!() }
    fn remove_fabric(&mut self, data: Option<TLV>) -> Vec<InvokeResponse> { todo!() }
    fn add_trusted_root_certificate(&mut self, data: Option<TLV>) -> Vec<InvokeResponse> { todo!() }
}

impl ClusterImplementation for OperationalCredentialsCluster {
    fn read_attributes(&self, attribute_path: AttributePath) -> Vec<AttributeReport> {
        match attribute_path.attribute_id {
            QueryParameter::Wildcard => {
                todo!("Reading of this cluster has not been implemented yet.")
            }
            QueryParameter::Specific(id) => {
                todo!("Reading of this cluster has not been implemented yet.")
            }
        }
    }

    fn as_any(&mut self) -> &mut dyn Any {
        self
    }

    fn invoke_command(&mut self, command: CommandData, session: &mut Session) -> Vec<InvokeResponse> {
        let data = command.fields;
        match command.path.command_id {
            QueryParameter::Wildcard => {
                todo!("Reading of this cluster has not been implemented yet.")
            }
            QueryParameter::Specific(command_id) => {
                match command_id {
                    0x00 => self.attestation_request(data, session),
                    0x02 => self.certificate_chain_request(data),
                    0x04 => self.csr_request(data),
                    0x06 => self.add_noc(data),
                    0x07 => self.update_noc(data),
                    0x09 => self.update_fabric_label(data),
                    0x0A => self.remove_fabric(data),
                    0x0B => self.add_trusted_root_certificate(data),
                    _ => todo!("Not implemented command!")
                }
            }
        }
    }
}

#[derive(Debug)]
#[repr(u8)]
pub enum CertificateChainType {
    DAC = 1,
    PAI = 2,
}

pub enum OperationalCertificateStatus {
    Ok = 0,
    InvalidPublicKey = 1,
    InvalidNodeOpId = 2,
    InvalidNOC = 3,
    MissingCsr = 4,
    TableFull = 5,
    InvalidAdminSubject = 6,
    FabricConflict = 9,
    LabelConflict = 10,
    InvalidFabricIndex = 11,
}

/// `noc`: Node Operational Certificate
///
/// `icac`: Intermediate Certificate Authority Certificate
pub struct NOC {
    noc: Vec<u8>,
    icac: Vec<u8>,
}

pub struct FabricDescriptor {
    root_public_key: Vec<u8>,
    vendor_id: u16,
    fabric_id: u64,
    node_id: u64,
    label: String,
}

pub struct CertificationDeclaration {
    pub format_version: u16,
    pub vendor_id: u16,
    pub product_id: Vec<u16>,
    pub device_type_id: u32,
    pub certificate_id: String,
    pub security_level: u8,
    pub security_information: u16,
    pub version_number: u16,
    pub certification_type: u8,
    pub dac_origin_vendor_id: Option<u16>,
    pub dac_origin_product_id: Option<u16>,
    // ToDo: Add later... authorized_paa_list: Option<[[u8; 20]; 10]>,
}

impl CertificationDeclaration {
    pub fn new() -> Self {
        Self {
            format_version: 1,
            vendor_id: 0xFFF1,
            product_id: vec![0x8000],
            device_type_id: 22,
            certificate_id: "CSA00000SWC00000-00".to_string(),
            security_level: 0,
            security_information: 0,
            version_number: 1,
            certification_type: 0,            // 0 = Test, 1 = Provisional/In certification, 2 = official
            dac_origin_vendor_id: None,
            dac_origin_product_id: None,
        }
    }
}

impl From<CertificationDeclaration> for ElementType {
    fn from(value: CertificationDeclaration) -> Self {
        Structure(vec![
            TLV::new(value.format_version.into(), ContextSpecific8, Tag::simple(Short(0))),
            TLV::new(value.vendor_id.into(), ContextSpecific8, Tag::simple(Short(1))),
            TLV::new(value.product_id.into(), ContextSpecific8, Tag::simple(Short(2))),
            TLV::new(value.device_type_id.into(), ContextSpecific8, Tag::simple(Short(3))),
            TLV::new(value.certificate_id.into(), ContextSpecific8, Tag::simple(Short(4))),
            TLV::new(value.security_level.into(), ContextSpecific8, Tag::simple(Short(5))),
            TLV::new(value.security_information.into(), ContextSpecific8, Tag::simple(Short(6))),
            TLV::new(value.version_number.into(), ContextSpecific8, Tag::simple(Short(7))),
            TLV::new(value.certification_type.into(), ContextSpecific8, Tag::simple(Short(8))),
            // TLV::new(value.dac_origin_vendor_id.into(), ContextSpecific8, Tag::simple(Short(9))),
            // TLV::new(value.dac_origin_product_id.into(), ContextSpecific8, Tag::simple(Short(10))),
            // TLV::new(value.authorized_paa_list.into(), ContextSpecific8, Tag::simple(Short(11))),
        ])
    }
}

impl From<Vec<u16>> for ElementType {
    fn from(value: Vec<u16>) -> Self {
        Array(value.into_iter().map(|x| TLV::simple(x.into())).collect())
    }
}

impl<T: Into<ElementType>> From<Option<T>> for ElementType {
    fn from(value: Option<T>) -> Self {
        if let Some(value) = value { value.into() } else {
            panic!("Not implemented yet...")
        }
    }
}


#[derive(Sequence)]
pub struct Pkcs7SignedData {
    pub algorithm: ObjectIdentifier,
    pub value: ContextSpecific<DerCertificationDeclaration>,
}

#[derive(Sequence, ValueOrd)]
pub struct DigestAlgorithmIdentifier {
    pub algorithm: ObjectIdentifier,
}

#[derive(Sequence)]
pub struct DerCertificationDeclaration {
    pub version: der::asn1::Int,
    pub digest_algorithm: der::asn1::SetOf<DigestAlgorithmIdentifier, 1>,
    pub encapsulated_content: EncapsulatedContentInfo,
    pub signer_info: SetOf<SignerInfo, 1>,
}

#[derive(Sequence)]
pub struct EncapsulatedContentInfo {
    pub content_type: ObjectIdentifier,
    pub content: ContextSpecific<OctetString>,
}

#[derive(Sequence, ValueOrd)]
pub struct SignerInfo {
    pub version: der::asn1::Int,
    pub subject_key_identifier: ContextSpecific<OctetString>,
    pub digest_algorithm: DigestAlgorithmIdentifier,
    pub signature_algorithm: DigestAlgorithmIdentifier,
    pub signature: OctetString,
}


/*// impl Encode for EncapsulatedContentInfo {
//     fn encoded_len(&self) -> p256::pkcs8::der::Result<Length> {
//         self.content_type.encoded_len()?
//             + self.content.encoded_len()?
//     }
//
//     fn encode(&self, encoder: &mut impl Writer) -> p256::pkcs8::der::Result<()> {
//         self.content_type.encode(encoder)?;
//         self.content.encode(encoder)?;
//         Ok(())
//     }
// }
*/

/*
impl Encode for SignerInfo {
    fn encoded_len(&self) -> der::Result<Length> {
        self.version.encoded_len()? + self.subject_key_identifier.encoded_len()?
            + self.digest_algorithm.encoded_len()?
            + self.signature_algorithm.encoded_len()?
            + self.signature.encoded_len()?
    }

    fn encode(&self, encoder: &mut impl Writer) -> der::Result<()> {
        self.version.encode(encoder)?;
        self.subject_key_identifier.encode(encoder)?;
        self.digest_algorithm.encode(encoder)?;
        self.signature_algorithm.encode(encoder)?;
        self.signature.encode(encoder)?;
        Ok(())
    }
}
*/
