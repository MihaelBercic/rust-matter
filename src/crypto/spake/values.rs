use crate::crypto::spake::values_initiator::ProverValues;
use crate::crypto::spake::values_responder::VerifierValues;

///
/// @author Mihael Berčič
/// @date 13. 9. 24
///
pub enum Values {
    SpakeVerifier(VerifierValues),
    SpakeProver(ProverValues),
}

