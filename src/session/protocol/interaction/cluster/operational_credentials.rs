use crate::session::protocol::interaction::cluster::ClusterImplementation;
use crate::session::protocol::interaction::enums::QueryParameter;
use crate::session::protocol::interaction::information_blocks::attribute::report::AttributeReport;
use crate::session::protocol::interaction::information_blocks::attribute::Attribute;
use crate::session::protocol::interaction::information_blocks::{AttributePath, CommandData, InvokeResponse};
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

    fn attestation_request() { todo!() }
    fn certificate_chain_request() { todo!() }
    fn csr_request() { todo!() }
    fn add_noc() { todo!() }
    fn update_noc() { todo!() }
    fn update_fabric_label() { todo!() }
    fn remove_fabric() { todo!() }
    fn add_trusted_root_certificate() { todo!() }
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
        match command.path.command_id {
            QueryParameter::Wildcard => {
                todo!("Reading of this cluster has not been implemented yet.")
            }
            QueryParameter::Specific(command_id) => {
                todo!("Reading of this cluster has not been implemented yet.")
            }
        }
    }
}


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