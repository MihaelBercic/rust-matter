use crate::constants::TEST_CERT_PAA_NO_VID_CERT;
use crate::session::protocol::interaction::cluster::operational_credentials::CertificateChainType::PAI;
use crate::session::protocol::interaction::cluster::ClusterImplementation;
use crate::session::protocol::interaction::enums::QueryParameter;
use crate::session::protocol::interaction::enums::QueryParameter::Specific;
use crate::session::protocol::interaction::information_blocks::attribute::report::AttributeReport;
use crate::session::protocol::interaction::information_blocks::attribute::Attribute;
use crate::session::protocol::interaction::information_blocks::{AttributePath, CommandData, CommandPath, InvokeResponse};
use crate::tlv::element_type::ElementType::Structure;
use crate::tlv::tag::Tag;
use crate::tlv::tag_control::TagControl::ContextSpecific8;
use crate::tlv::tag_number::TagNumber::Short;
use crate::tlv::tlv::TLV;
use crate::{log_debug, log_info};
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

    fn attestation_request(&mut self, data: Option<TLV>) -> Vec<InvokeResponse> {
        vec![
            InvokeResponse {
                command: Some(CommandData {
                    path: CommandPath::new(Specific(0x03)),
                    fields: Some(TLV::simple(Structure(vec![
                        TLV::new(hex::decode(TEST_CERT_PAA_NO_VID_CERT).unwrap().into(), ContextSpecific8, Tag::simple(Short(0))),
                        TLV::new(hex::decode(TEST_CERT_PAA_NO_VID_CERT).unwrap().into(), ContextSpecific8, Tag::simple(Short(1))),
                    ]))),
                }),
                status: None,
            }
        ]
    }
    fn certificate_chain_request(&mut self, data: Option<TLV>) -> Vec<InvokeResponse> {
        log_debug!("Certificate Chain Request invoke!");
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

    fn invoke_command(&mut self, command: CommandData) -> Vec<InvokeResponse> {
        let data = command.fields;
        match command.path.command_id {
            QueryParameter::Wildcard => {
                todo!("Reading of this cluster has not been implemented yet.")
            }
            QueryParameter::Specific(command_id) => {
                match command_id {
                    0x00 => self.attestation_request(data),
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