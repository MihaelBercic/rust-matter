use p256::ecdsa::SigningKey;

/// `noc`: Node Operational Certificate
///
/// `icac`: Intermediate Certificate Authority Certificate
#[derive(Clone, Debug)]
pub struct NOC {
    pub icac: Option<Vec<u8>>,
    pub noc: Vec<u8>,
    pub private_key: SigningKey,
}
