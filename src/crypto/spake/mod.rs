use crate::crypto::constants::{NIST_P_256_n, CRYPTO_GROUP_SIZE_BITS, CRYPTO_GROUP_SIZE_BYTES, CRYPTO_M_BYTES, CRYPTO_N_BYTES, CRYPTO_W_SIZE_BITS, CRYPTO_W_SIZE_BYTES};
use crate::crypto::kdf::key_derivation;
use crate::crypto::spake::spake_confirmation::S2PConfirmation;
use crate::crypto::spake::values::Values;
use crate::crypto::spake::values_initiator::ProverValues;
use crate::crypto::spake::values_responder::VerifierValues;
use crate::crypto::{hash_message, hmac, kdf};
use crate::utils::padding::Extensions;
use crate::utils::MatterError;
use byteorder::{WriteBytesExt, LE};
use crypto_bigint::{nlimbs, Encoding, NonZero, Random, Uint};
use p256::elliptic_curve::generic_array::GenericArray;
use p256::elliptic_curve::group::GroupEncoding;
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::elliptic_curve::{Field, PrimeField};
use p256::{AffinePoint, EncodedPoint, ProjectivePoint, Scalar};
use std::error::Error;
use std::ops::{Add, Mul, Rem};

///
/// @author Mihael Berčič
/// @date 7. 8. 24
///
pub mod values_initiator;
pub mod values_responder;
pub mod spake_confirmation;
pub mod values;

#[allow(non_snake_case)]
pub struct SPAKE2P {
    pub(crate) y: Scalar,
    pub(crate) x: Scalar,
    N: ProjectivePoint,
    M: ProjectivePoint,
}

impl SPAKE2P {
    /// Initialise Spake2+ instance with random values and storing N and M.
    pub fn new() -> Self {
        let mut rng = crypto_bigint::rand_core::OsRng;
        let random = Scalar::random(&mut rng);
        let n_encoded = EncodedPoint::from_bytes(CRYPTO_N_BYTES).unwrap();
        let m_encoded = EncodedPoint::from_bytes(CRYPTO_M_BYTES).unwrap();
        let n_projective = ProjectivePoint::from_encoded_point(&n_encoded).unwrap();
        let m_projective = ProjectivePoint::from_encoded_point(&m_encoded).unwrap();
        SPAKE2P {
            y: random.clone(),
            x: random,
            N: n_projective,
            M: m_projective,
        }
    }

    /// Computes the prover values (w0, w1) based on input.
    pub fn compute_prover(passcode: u32, salt: &[u8], iterations: u32) -> ProverValues {
        /*
        byte w0s[CRYPTO_W_SIZE_BYTES] || byte w1s[CRYPTO_W_SIZE_BYTES] = (byte[2 * CRYPTO_W_SIZE_BYTES])  bit[2 * CRYPTO_W_SIZE_BITS] Crypto_PBKDF(passcode, salt, iterations, 2 * CRYPTO_W_SIZE_BITS)
        byte w0[CRYPTO_GROUP_SIZE_BYTES] = w0s mod p
        byte w1[CRYPTO_GROUP_SIZE_BYTES] = w1s mod p
        */
        const REQUIRED_LIMBS: usize = { nlimbs!(CRYPTO_W_SIZE_BITS) };
        let order = NonZero::new(NIST_P_256_n.resize::<REQUIRED_LIMBS>()).unwrap();
        let pbkdf = kdf::password_key_derivation(&passcode.to_le_bytes(), salt, iterations, CRYPTO_W_SIZE_BITS * 2);
        const REQUIRED_OUTPUT: usize = { nlimbs!(CRYPTO_GROUP_SIZE_BITS) };
        let w0 = Uint::<REQUIRED_LIMBS>::from_be_slice(&pbkdf[0..CRYPTO_W_SIZE_BYTES]).rem(&order).resize::<REQUIRED_OUTPUT>().to_be_bytes();
        let w1 = Uint::<REQUIRED_LIMBS>::from_be_slice(&pbkdf[CRYPTO_W_SIZE_BYTES..]).rem(&order).resize::<REQUIRED_OUTPUT>().to_be_bytes();
        ProverValues {
            w0: w0[..CRYPTO_GROUP_SIZE_BYTES].try_into().unwrap(),
            w1: w1[..CRYPTO_GROUP_SIZE_BYTES].try_into().unwrap(),
        }
    }

    /// Computes the verifier values (w0, L) based on input.
    pub fn compute_verifier(passcode: u32, salt: &[u8], iterations: u32) -> VerifierValues {
        // L = w1 * P
        let prover = Self::compute_prover(passcode, salt, iterations);
        let w1_scalar = Scalar::from_repr(*GenericArray::from_slice(&prover.w1)).unwrap();
        let length = (AffinePoint::GENERATOR * w1_scalar).to_encoded_point(false).to_bytes();
        VerifierValues {
            w0: prover.w0,
            L: (&length[..]).try_into().unwrap(),
        }
    }

    /// Computes the prover public key (X).
    pub fn compute_public_prover(&self, w0: &[u8]) -> ProjectivePoint {
        // x <- [0, p-1]
        // X = x*P + w0*M
        let w0_scalar = Scalar::from_repr(*GenericArray::from_slice(&w0)).unwrap();
        ProjectivePoint::GENERATOR.mul(self.x).add(self.M.mul(&w0_scalar))
    }

    /// Computes the verifier public key (Y).
    pub fn compute_public_verifier(&self, w0: &[u8]) -> ProjectivePoint {
        // y <- [0, p-1]
        // Y = y*P + w0*N
        let w0_scalar = Scalar::from_repr(*GenericArray::from_slice(&w0)).unwrap();
        ProjectivePoint::GENERATOR.mul(self.y).add(self.N.mul(&w0_scalar))
    }

    /// Computes TT from (X,Y,Z,V, w0 and context).
    pub fn compute_transcript(&self, context: &[u8], id_p: &[u8], id_v: &[u8], values: Values, p_a: &[u8], p_b: &[u8]) -> Vec<u8> {
        let mut w0 = match &values {
            Values::SpakeVerifier(r) => r.w0,
            Values::SpakeProver(i) => i.w0
        };

        let (z, v) = self.compute_shared_values(&values, p_a, p_b);
        let mut data = vec![];
        write_with_length(&mut data, context);
        write_with_length(&mut data, id_p);
        write_with_length(&mut data, id_v);
        write_with_length(&mut data, self.M.to_encoded_point(false).as_bytes());
        write_with_length(&mut data, self.N.to_encoded_point(false).as_bytes());
        write_with_length(&mut data, p_a);
        write_with_length(&mut data, p_b);
        write_with_length(&mut data, z.to_encoded_point(false).as_bytes());
        write_with_length(&mut data, v.to_encoded_point(false).as_bytes());
        write_with_length(&mut data, &w0);
        data
    }

    // Computes (Z, V) pair.
    pub fn compute_shared_values(&self, values: &Values, p_a: &[u8], p_b: &[u8]) -> (ProjectivePoint, ProjectivePoint) {
        // Apparently h === 1 in P256.
        let public_prover = ProjectivePoint::from_encoded_point(&EncodedPoint::from_bytes(&p_a).unwrap()).unwrap();
        let public_verifier = ProjectivePoint::from_encoded_point(&EncodedPoint::from_bytes(&p_b).unwrap()).unwrap();
        match values {
            Values::SpakeVerifier(responder) => {
                // VERIFIER:   Z = h*y*(X - w0*M)      V = h*y*L
                let w0_scalar = Scalar::from_repr(responder.w0.into()).unwrap();
                let l = ProjectivePoint::from_encoded_point(&EncodedPoint::from_bytes(&responder.L).unwrap()).unwrap();
                let z = (public_prover - (self.M * w0_scalar)) * self.y;
                let v = l * self.y;
                (z, v)
            }
            Values::SpakeProver(initiator) => {
                todo!("Not implemented yet...");
                // // PROVER:     Z = h*x*(Y - w0*N)      V = h*w1*(Y - w0*N)
                // let w_t_n = self.N * Scalar::from_repr(initiator.w0.into()).unwrap();
                // let Z = (public_verifier - w_t_n) * Scalar::from_repr(self.x.into()).unwrap();
                // let V = (public_verifier - w_t_n) * Scalar::from_repr(initiator.w1.into()).unwrap();
                // (Z, V)
            }
        }
    }

    /// Computes confirmation values for the provided transcript.
    pub fn compute_confirmation_values(&self, tt: &Vec<u8>, p_a: &[u8], p_b: &[u8], bit_length: usize) -> S2PConfirmation {
        let k_main = hash_message(tt);
        let k_a = &k_main[..16];
        let k_e = &k_main[16..];
        let k_confirm = key_derivation(k_a, None, b"ConfirmationKeys", bit_length);
        S2PConfirmation {
            cA: hmac(&k_confirm[..16], p_b),
            cB: hmac(&k_confirm[16..], p_a),
            Ke: k_e.try_into().unwrap(),
        }
    }
}


fn write_with_length(vec: &mut Vec<u8>, data: &[u8]) -> Result<(), MatterError> {
    vec.write_u64::<LE>(data.len() as u64)?;
    vec.extend_from_slice(data);
    Ok(())
}