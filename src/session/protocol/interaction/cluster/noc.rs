use p256::ecdsa::SigningKey;

use crate::crypto::constants::CERTIFICATE_SIZE;

/// `noc`: Node Operational Certificate
///
/// `icac`: Intermediate Certificate Authority Certificate
#[derive(Clone, Debug)]
pub struct NOC {
    pub icac: Option<Vec<u8>>,
    pub noc: Vec<u8>,
    pub private_key: SigningKey,
}
