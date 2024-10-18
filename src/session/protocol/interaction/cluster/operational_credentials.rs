use crate::constants::TEST_CERT_PAA_NO_VID_CERT;
use crate::crypto::{compute_certificate, sign_message_with_signature, KeyPair};
use crate::log_info;
use crate::mdns::enums::DeviceType::Thermostat;
use crate::session::protocol::interaction::cluster::enums::CertificateChainType::{self, *};
use crate::session::protocol::interaction::cluster::ClusterImplementation;
use crate::session::protocol::interaction::enums::QueryParameter;
use crate::session::protocol::interaction::enums::QueryParameter::Specific;
use crate::session::protocol::interaction::information_blocks::attribute::report::AttributeReport;
use crate::session::protocol::interaction::information_blocks::attribute::Attribute;
use crate::session::protocol::interaction::information_blocks::{AttributePath, CommandData, CommandPath, InvokeResponse};
use crate::session::session::Session;
use crate::tlv::element_type::ElementType;
use crate::tlv::element_type::ElementType::{Array, OctetString16, Structure};
use crate::tlv::tag::Tag;
use crate::tlv::tag_control::TagControl::ContextSpecific8;
use crate::tlv::tag_number::TagNumber::Short;
use crate::tlv::tlv::Tlv;
use der::asn1::{ContextSpecific, ObjectIdentifier, OctetString, SetOf};
use der::{Encode, Sequence, ValueOrd};
use p256::ecdsa::SigningKey;
use p256::NistP256;
use sec1::DecodeEcPrivateKey;
use std::any::Any;
use std::fs;

use super::{FabricDescriptor, NOC};

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
    pub temporary_key_pair: Option<KeyPair>,
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
            temporary_key_pair: None,
        }
    }

    fn attestation_request(&mut self, data: Option<Tlv>, session: &mut Session) -> Vec<InvokeResponse> {
        let data = data.unwrap();
        let Structure(children) = data.control.element_type else {
            panic!("Yeah incorrect data...");
        };
        let nonce = children.first().unwrap().to_owned().control.element_type.into_octet_string().unwrap();
        let certificate = fs::read("certification_declaration.der").expect("Missing file.");

        let attestation_elements = Tlv::simple(Structure(vec![
            Tlv::new(OctetString16(certificate.clone()), ContextSpecific8, Tag::short(1)),
            Tlv::new(nonce.into(), ContextSpecific8, Tag::short(2)),
            Tlv::new((677103357u32).into(), ContextSpecific8, Tag::short(3)),
        ]))
        .to_bytes();

        let mut tbs = attestation_elements.clone();
        tbs.extend_from_slice(&session.attestation_challenge);

        let path = fs::read("attestation/Chip-Test-DAC-FFF1-8000-0000-Key.der").expect("Missing file");
        let key: SigningKey = SigningKey::from_sec1_der(&path).expect("Unable to create key");
        let signature = sign_message_with_signature(&key, &tbs);
        println!("Signature length: {}", signature.clone().to_vec().len());

        vec![InvokeResponse {
            command: Some(CommandData {
                path: CommandPath::new(Specific(0x01)),
                fields: Some(Tlv::simple(Structure(vec![
                    Tlv::new(attestation_elements.into(), ContextSpecific8, Tag::short(0)),
                    Tlv::new(signature.to_vec().into(), ContextSpecific8, Tag::short(1)),
                ]))),
            }),
            status: None,
        }]
    }
    fn certificate_chain_request(&mut self, data: Option<Tlv>) -> Vec<InvokeResponse> {
        let mut chain: CertificateChainType = CertificateChainType::DAC;
        if let Some(tlv) = data {
            if let Structure(data) = tlv.control.element_type {
                for child in data {
                    let chain_type = child.control.element_type.into_u8().unwrap();
                    let chain_type = if chain_type == 1 { CertificateChainType::DAC } else { PAI };
                    log_info!("Working with certificate type: {:?}", chain_type);
                    chain = chain_type;
                }
            }
        }
        let certificate = if chain == CertificateChainType::DAC {
            fs::read("attestation/Chip-Test-DAC-FFF1-8000-0000-Cert.der").unwrap()
        } else {
            fs::read("attestation/Chip-Test-PAI-FFF1-8000-Cert.der").unwrap()
        };
        vec![InvokeResponse {
            command: Some(CommandData {
                path: CommandPath::new(Specific(0x03)),
                fields: Some(Tlv::simple(Structure(vec![Tlv::new(
                    certificate.into(),
                    ContextSpecific8,
                    Tag::short(0),
                )]))),
            }),
            status: None,
        }]
    }

    /// v1.3 Core Specification 11.17.6.5
    /// Execute the Node Operational CSR Procedure
    /// Return NOCSR Information in the form of [CSRResponseCommand]
    fn csr_request(&mut self, data: Option<Tlv>) -> Vec<InvokeResponse> {
        let mut responses = vec![];
        if let Some(data) = data {
            let request = CsrRequest::from(data);
            let key_pair = crate::crypto::generate_key_pair();
            self.temporary_key_pair = Some(key_pair);
        }
        responses
    }
    fn add_noc(&mut self, data: Option<Tlv>) -> Vec<InvokeResponse> {
        todo!()
    }
    fn update_noc(&mut self, data: Option<Tlv>) -> Vec<InvokeResponse> {
        todo!()
    }
    fn update_fabric_label(&mut self, data: Option<Tlv>) -> Vec<InvokeResponse> {
        todo!()
    }
    fn remove_fabric(&mut self, data: Option<Tlv>) -> Vec<InvokeResponse> {
        todo!()
    }
    fn add_trusted_root_certificate(&mut self, data: Option<Tlv>) -> Vec<InvokeResponse> {
        todo!()
    }
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
            QueryParameter::Specific(command_id) => match command_id {
                0x00 => self.attestation_request(data, session),
                0x02 => self.certificate_chain_request(data),
                0x04 => self.csr_request(data),
                0x06 => self.add_noc(data),
                0x07 => self.update_noc(data),
                0x09 => self.update_fabric_label(data),
                0x0A => self.remove_fabric(data),
                0x0B => self.add_trusted_root_certificate(data),
                _ => todo!("Not implemented command!"),
            },
        }
    }
}

struct CsrRequest {
    csr_nonce: [u8; 32],
    is_for_update_noc: bool,
}

/// TODO: Change into TryFrom
impl From<Tlv> for CsrRequest {
    fn from(value: Tlv) -> Self {
        let mut request = CsrRequest {
            csr_nonce: Default::default(),
            is_for_update_noc: false,
        };
        let Structure(children) = value.control.element_type else {
            return request;
        };

        for child in children {
            let Some(Short(tag_number)) = child.tag.tag_number else {
                return request;
            };
            match tag_number {
                0 => request.csr_nonce = child.control.element_type.into_octet_string().unwrap().try_into().unwrap(),
                1 => request.is_for_update_noc = child.control.element_type.into_boolean().unwrap(),
                _ => (),
            }
        }

        request
    }
}
