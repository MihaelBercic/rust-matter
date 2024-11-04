use crate::constants::TEST_CERT_PAA_NO_VID_CERT;
use crate::crypto::constants::CRYPTO_PUBLIC_KEY_SIZE_BYTES;
use crate::crypto::kdf::key_derivation;
use crate::crypto::{self, kdf, sign_message_with_signature};
use crate::mdns::device_information::DeviceInformation;
use crate::mdns::enums::CommissionState;
use crate::mdns::enums::DeviceType::Thermostat;
use crate::session::protocol::interaction::cluster::enums::CertificateChainType::{self, *};
use crate::session::protocol::interaction::cluster::ClusterImplementation;
use crate::session::protocol::interaction::enums::QueryParameter::Specific;
use crate::session::protocol::interaction::enums::{GlobalStatusCode, QueryParameter};
use crate::session::protocol::interaction::information_blocks::attribute::report::AttributeReport;
use crate::session::protocol::interaction::information_blocks::attribute::status::Status;
use crate::session::protocol::interaction::information_blocks::attribute::Attribute;
use crate::session::protocol::interaction::information_blocks::{AttributePath, CommandData, CommandPath, CommandStatus, InvokeResponse};
use crate::session::session::Session;
use crate::tlv::element_type::ElementType;
use crate::tlv::element_type::ElementType::{Array, OctetString16, Structure};
use crate::tlv::tag::Tag;
use crate::tlv::tag_control::TagControl::ContextSpecific8;
use crate::tlv::tag_number;
use crate::tlv::tag_number::TagNumber::Short;
use crate::tlv::tlv::Tlv;
use crate::utils::{bail_generic, bail_tlv, MatterError};
use crate::{log_debug, log_info};
use der::asn1::{ContextSpecific, ObjectIdentifier, OctetString, SetOf};
use der::oid::AssociatedOid;
use der::{Decode, Encode, FixedTag, Sequence, ValueOrd};
use p256::ecdsa::{self, DerSignature, SigningKey, VerifyingKey};
use p256::NistP256;
use sec1::DecodeEcPrivateKey;
use signature::Signer;
use std::any::Any;
use std::fs;
use std::str::FromStr;
use x509_cert::builder::{Builder, RequestBuilder};
use x509_cert::name::{Name, RdnSequence};
use x509_cert::spki::{AlgorithmIdentifierOwned, AlgorithmIdentifierWithOid, DynSignatureAlgorithmIdentifier};

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
    pub pending_key_pair: Option<SigningKey>,
    pub working_on: CertificateChainType,
    pub pending_root_cert: Vec<u8>,
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
            pending_key_pair: None,
            working_on: CertificateChainType::DAC,
            pending_root_cert: vec![],
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
            self.working_on = DAC;
            fs::read("attestation/Chip-Test-DAC-FFF1-8000-0000-Cert.der").unwrap()
        } else {
            self.working_on = PAI;
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
    fn csr_request(&mut self, data: Option<Tlv>, session: &mut Session) -> Vec<InvokeResponse> {
        let mut responses = vec![];
        if let Some(data) = data {
            let request = CsrRequest::from(data);
            let key_pair = crate::crypto::generate_key_pair();
            let subject = Name::from_str("O=CSA").unwrap();

            let mut builder = RequestBuilder::new(subject, &key_pair).expect("Create CSR.");
            let csr = builder.build::<DerSignature>().unwrap().to_der().unwrap();

            self.pending_key_pair = Some(key_pair.clone());
            println!("Signature: {}", hex::encode(&csr));
            let elements = Tlv::simple(Structure(vec![
                Tlv::new(csr.into(), ContextSpecific8, Tag::short(1)),
                Tlv::new(request.csr_nonce.into(), ContextSpecific8, Tag::short(2)),
            ]));
            let mut tbs = elements.clone().to_bytes();
            tbs.extend_from_slice(&session.attestation_challenge);

            let path = fs::read("attestation/Chip-Test-DAC-FFF1-8000-0000-Key.der").expect("Missing file");
            let key: SigningKey = SigningKey::from_sec1_der(&path).expect("Unable to create key");
            let signature = sign_message_with_signature(&key, &tbs);

            let response = InvokeResponse {
                command: Some(CommandData {
                    path: CommandPath::new(Specific(0x5)),
                    fields: Some(Tlv::simple(Structure(vec![
                        Tlv::new(elements.to_bytes().into(), ContextSpecific8, Tag::short(0)),
                        Tlv::new(signature.to_vec().into(), ContextSpecific8, Tag::short(1)),
                    ]))),
                }),
                status: None,
            };
            responses.push(response);
        }
        responses
    }

    fn add_noc(&mut self, data: Option<Tlv>) -> Vec<InvokeResponse> {
        // check if valid key
        // check if can save fabric
        // store NOC
        // store the fabric
        // generate the group key
        let mut responses = vec![];
        if let Some(tlv) = data {
            let parameters = AddNocParameters::try_from(tlv).expect("Yeah should've parsed.");

            let noc = MatterCertificate::try_from(&parameters.noc_value[..]).unwrap();
            let Some(private_key) = &self.pending_key_pair else {
                panic!("Missing key pair");
            };

            let public_key = private_key.verifying_key();
            let pbk_bytes = public_key.to_sec1_bytes().to_vec();

            if pbk_bytes != noc.ec_public_key {
                panic!("Invalid public key... {} vs {}", hex::encode(pbk_bytes), hex::encode(noc.ec_public_key))
            }

            let root_cert = MatterCertificate::try_from(&self.pending_root_cert[..]).unwrap();

            let new_fabric = FabricDescriptor {
                root_public_key: root_cert.ec_public_key.clone().into(),
                vendor_id: parameters.admin_vendor_id,
                fabric_id: noc.subject.matter_fabric_id,
                node_id: noc.subject.matter_node_id,
                label: "Not sure".to_string(),
            };
            log_info!("Adding fabric {} with node id {}", new_fabric.fabric_id, new_fabric.node_id);
            let fabric_id = noc.subject.matter_fabric_id.to_be_bytes();
            let compressed_fabric_id = key_derivation(&root_cert.ec_public_key[1..], Some(&fabric_id), b"CompressedFabric", 64);
            let compressed_as_hex = hex::encode_upper(&compressed_fabric_id);
            let node_id = hex::encode_upper(new_fabric.node_id.to_be_bytes());
            let instance_name = format!("{}-{}", compressed_as_hex, node_id);
            log_info!("Will start advertising _matterc._tcp with name {}", instance_name);
            responses.push(InvokeResponse {
                command: Some(CommandData {
                    path: CommandPath::new(Specific(0x08)),
                    fields: Some(Tlv::simple(Structure(vec![Tlv::new(0u8.into(), ContextSpecific8, Tag::short(0))]))),
                }),
                status: None,
            });
        }
        responses
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
    fn add_trustexd_root_certificate(&mut self, data: Option<Tlv>, information: &mut DeviceInformation) -> Vec<InvokeResponse> {
        if let Some(data) = data {
            if let Structure(children) = data.control.element_type {
                for child in children {
                    if let Some(Short(tag_number)) = child.tag.tag_number {
                        match tag_number {
                            0 => self.pending_root_cert = child.control.element_type.into_octet_string().unwrap(),
                            _ => log_debug!("Tag number received: {}", tag_number),
                        }
                    }
                }
            }
        }
        vec![InvokeResponse {
            command: None,
            status: Some(CommandStatus {
                path: CommandPath::new(Specific(0x0B)),
                status: Status {
                    status: GlobalStatusCode::Success as u8,
                    cluster_status: 0,
                },
            }),
        }]
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

    fn invoke_command(&mut self, command: CommandData, session: &mut Session, information: &mut DeviceInformation) -> Vec<InvokeResponse> {
        let data = command.fields;
        match command.path.command_id {
            QueryParameter::Wildcard => {
                todo!("Reading of this cluster has not been implemented yet.")
            }
            QueryParameter::Specific(command_id) => match command_id {
                0x00 => self.attestation_request(data, session),
                0x02 => self.certificate_chain_request(data),
                0x04 => self.csr_request(data, session),
                0x06 => self.add_noc(data),
                0x07 => self.update_noc(data),
                0x09 => self.update_fabric_label(data),
                0x0A => self.remove_fabric(data),
                0x0B => self.add_trustexd_root_certificate(data, information),
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

pub struct AddNocParameters {
    pub noc_value: Vec<u8>,
    pub icac_value: Option<Vec<u8>>,
    pub ipk_value: Vec<u8>,
    pub case_admin_subject: u64,
    pub admin_vendor_id: u16,
}

impl TryFrom<Tlv> for AddNocParameters {
    type Error = MatterError;

    fn try_from(value: Tlv) -> Result<Self, Self::Error> {
        let mut parameters = Self {
            noc_value: vec![],
            icac_value: None,
            ipk_value: vec![],
            case_admin_subject: 0,
            admin_vendor_id: 0,
        };
        let Structure(children) = value.control.element_type else {
            bail_tlv!("Incorrect Tlv structure...");
        };

        for child in children {
            let Some(Short(tag_number)) = child.tag.tag_number else {
                bail_tlv!("Missing tag number!");
            };
            let element = child.control.element_type;
            match tag_number {
                0 => parameters.noc_value = element.into_octet_string().unwrap(),
                1 => parameters.icac_value = Some(element.into_octet_string().unwrap()),
                2 => parameters.ipk_value = element.into_octet_string().unwrap(),
                3 => parameters.case_admin_subject = element.into_u64().unwrap(),
                4 => parameters.admin_vendor_id = element.into_u16().unwrap(),
                _ => log_debug!("Not covered TAG_NUMBER {}", tag_number),
            }
        }

        Ok(parameters)
    }
}

/// Core spec v1.2 - Page 317 - 6.5.2
pub struct MatterCertificate {
    pub serial_number: Vec<u8>,
    pub ec_public_key: Vec<u8>,
    pub subject: DnAttribute,
}

impl TryFrom<&[u8]> for MatterCertificate {
    type Error = MatterError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let tlv = Tlv::try_from(value)?;
        let mut certificate = Self {
            serial_number: vec![],
            ec_public_key: vec![],
            subject: DnAttribute {
                matter_fabric_id: 0,
                matter_node_id: 0,
            },
        };

        let Structure(children) = tlv.control.element_type else {
            bail_tlv!("Incorrect certificate tlv structure.")
        };

        for child in children {
            let element_type = child.control.element_type;
            let Some(Short(tag_number)) = child.tag.tag_number else {
                bail_tlv!("Missing tag number")
            };
            match tag_number {
                1 => certificate.serial_number = element_type.into_octet_string()?,
                6 => certificate.subject = DnAttribute::try_from(element_type)?,
                9 => certificate.ec_public_key = element_type.into_octet_string()?,
                _ => log_info!("Tag {} not implemented yet.", tag_number),
            }
        }

        Ok(certificate)
    }
}

pub struct DnAttribute {
    pub matter_fabric_id: u64,
    pub matter_node_id: u64,
}

impl TryFrom<ElementType> for DnAttribute {
    type Error = MatterError;

    fn try_from(value: ElementType) -> Result<Self, Self::Error> {
        let ElementType::List(children) = value else {
            bail_tlv!("Incorrect data structure.");
        };
        let mut dn = Self {
            matter_fabric_id: 0,
            matter_node_id: 0,
        };

        for child in children {
            let element = child.control.element_type;
            let Some(Short(tag_number)) = child.tag.tag_number else {
                bail_tlv!("Missing tag number...");
            };
            match tag_number {
                17 => dn.matter_node_id = element.into_u64()?,
                21 => dn.matter_fabric_id = element.into_u64()?,
                _ => log_debug!("Tag number {} Not implemented.", tag_number),
            }
        }
        Ok(dn)
    }
}
