use crate::crypto::constants::{BYTES_M, BYTES_N, CRYPTO_GROUP_SIZE_BITS, CRYPTO_GROUP_SIZE_BYTES, CRYPTO_HASH_LEN_BYTES, CRYPTO_W_SIZE_BITS, CRYPTO_W_SIZE_BYTES, NIST_P_256_N, NIST_P_256_ORDER};
use crate::crypto::kdf::key_derivation;
use crate::crypto::spake::values_initiator::ValuesInitiator;
use crate::crypto::spake::values_responder::VerifierValues;
use crate::crypto::{hash_message, hmac, kdf, random_bytes};
use crate::utils::padding::Extensions;
use crate::utils::MatterError;
use byteorder::{WriteBytesExt, LE};
use crypto_bigint::{nlimbs, Encoding, NonZero, Random, Uint, U256};
use p256::elliptic_curve::generic_array::GenericArray;
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::elliptic_curve::PrimeField;
use p256::{AffinePoint, EncodedPoint, ProjectivePoint, Scalar};
use std::error::Error;
use std::ops::Rem;

///
/// @author Mihael Berčič
/// @date 7. 8. 24
///
/// Y = p_B
/// Z, V = shared
/// X = p_A
/// x = random 32B
/// y = random 32B
pub mod values_initiator;
pub mod values_responder;

#[allow(non_snake_case)]
pub struct SPAKE2P {
    pub(crate) y: [u8; 32],
    pub(crate) x: [u8; 32],
    N: AffinePoint,
    M: AffinePoint,
}

impl SPAKE2P {
    pub fn new() -> Self {
        let random = generate_random();
        let random = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31];
        SPAKE2P {
            y: random.clone(),
            x: random,
            N: AffinePoint::from_encoded_point(&EncodedPoint::from_bytes(&BYTES_N).unwrap()).unwrap(),
            M: AffinePoint::from_encoded_point(&EncodedPoint::from_bytes(&BYTES_M).unwrap()).unwrap(),
        }
    }

    pub fn new_values(x: [u8; 32], y: [u8; 32]) -> Self {
        SPAKE2P {
            y,
            x,
            N: AffinePoint::from_encoded_point(&EncodedPoint::from_bytes(&BYTES_N).unwrap()).unwrap(),
            M: AffinePoint::from_encoded_point(&EncodedPoint::from_bytes(&BYTES_M).unwrap()).unwrap(),
        }
    }


    /// Computes SPAKE Initiator values (also referred to as Commissioner PAKE input).
    pub fn compute_values_initiator(&self, passcode: &[u8], salt: &[u8], iterations: u32) -> ValuesInitiator {
        /*
        byte w0s[CRYPTO_W_SIZE_BYTES] || byte w1s[CRYPTO_W_SIZE_BYTES] = (byte[2 * CRYPTO_W_SIZE_BYTES])  bit[2 * CRYPTO_W_SIZE_BITS] Crypto_PBKDF(passcode, salt, iterations, 2 * CRYPTO_W_SIZE_BITS)
        byte w0[CRYPTO_GROUP_SIZE_BYTES] = w0s mod p
        byte w1[CRYPTO_GROUP_SIZE_BYTES] = w1s mod p
        */
        const REQUIRED_LIMBS: usize = { nlimbs!(CRYPTO_W_SIZE_BITS) };
        let order = NIST_P_256_N.resize::<REQUIRED_LIMBS>();
        let order = NonZero::new(order).unwrap();
        let pbkdf = kdf::password_key_derivation(passcode, salt, iterations, CRYPTO_W_SIZE_BITS * 2);
        const REQUIRED_OUTPUT: usize = { nlimbs!(CRYPTO_GROUP_SIZE_BITS) };
        let w0 = Uint::<REQUIRED_LIMBS>::from_be_slice(&pbkdf[0..CRYPTO_W_SIZE_BYTES]).rem(&order).resize::<REQUIRED_OUTPUT>().to_be_bytes();
        let w1 = Uint::<REQUIRED_LIMBS>::from_be_slice(&pbkdf[CRYPTO_W_SIZE_BYTES..]).rem(&order).resize::<REQUIRED_OUTPUT>().to_be_bytes();

        // let w1 = w0.rem(&order).to_be_bytes();
        ValuesInitiator {
            w0: w0[..CRYPTO_GROUP_SIZE_BYTES].try_into().unwrap(),
            w1: w1[..CRYPTO_GROUP_SIZE_BYTES].try_into().unwrap(),
        }
    }

    pub fn compute_values_responder(&self, passcode: &[u8], salt: &[u8], iterations: u32) -> VerifierValues {
        let values_initiator = self.compute_values_initiator(passcode, salt, iterations);
        let w1_scalar = Scalar::from_repr(*GenericArray::from_slice(&values_initiator.w1)).unwrap();
        let length = (AffinePoint::GENERATOR * w1_scalar).to_encoded_point(false).to_bytes();
        VerifierValues {
            w0: values_initiator.w0,
            L: (&length[..]).try_into().unwrap(),
        }
    }

    #[allow(non_snake_case)]
    pub fn compute_pB(&self, values_responder: &VerifierValues) -> ProjectivePoint {
        // y <- [0, p-1]
        // Y = y*P + w0*N
        let w_s = Scalar::from_repr(*GenericArray::from_slice(&values_responder.w0)).unwrap();
        let y_s = Scalar::from_repr(*GenericArray::from_slice(&self.y)).unwrap();
        (ProjectivePoint::GENERATOR * y_s) + (self.N * w_s)
    }

    #[allow(non_snake_case)]
    pub fn compute_pA(&self, values_initiator: &ValuesInitiator) -> ProjectivePoint {
        // x <- [0, p-1]
        // X = x*P + w0*M
        let w_s = Scalar::from_repr(*GenericArray::from_slice(&values_initiator.w0)).unwrap();
        let x_s = Scalar::from_repr(*GenericArray::from_slice(&self.x)).unwrap();
        (AffinePoint::GENERATOR * x_s) + (self.M * w_s)
    }


    #[allow(unused_variables)]
    #[allow(non_snake_case)]
    pub fn compute_transcript(&self, context: &[u8], id_p: &[u8], id_v: &[u8], values: Values, p_a: &[u8], p_b: &[u8]) -> Vec<u8> {
        /*
        Context := Crypto_Hash(ContextPrefixValue || PBKDFParamRequest || PBKDFParamResponse)
        TT :=     lengthInBytes(Context)  || Context            ||
                    0x0000000000000000      || 0x0000000000000000 ||
                    lengthInBytes(M)        || M                  ||
                    lengthInBytes(N)        || N                  ||
                    lengthInBytes(pA)       || pA                 ||
                    lengthInBytes(pB)       || pB                 ||
                    lengthInBytes(Z)        || Z                  ||
                    lengthInBytes(V)        || V                  ||
                    lengthInBytes(w0)       || w0
        */
        let mut w0 = match &values {
            Values::Verifier(r) => r.w0,
            Values::Prover(i) => i.w0
        };

        let (Z, V) = self.compute_shared(values, p_b, p_a);
        let Z_as_bytes = Z.to_encoded_point(false).as_bytes().to_vec();
        let V_as_bytes = V.to_encoded_point(false).as_bytes().to_vec();

        println!("Z = {}", hex::encode(&Z_as_bytes));
        println!("V = {}", hex::encode(&V_as_bytes));

        let mut data = vec![];
        write_with_length(&mut data, context);
        write_with_length(&mut data, id_p);
        write_with_length(&mut data, id_v);
        write_with_length(&mut data, self.M.to_encoded_point(false).as_bytes());
        write_with_length(&mut data, self.N.to_encoded_point(false).as_bytes());
        write_with_length(&mut data, p_a);
        write_with_length(&mut data, p_b);
        write_with_length(&mut data, &Z_as_bytes);
        write_with_length(&mut data, &V_as_bytes);
        write_with_length(&mut data, &w0);
        data
    }


    #[allow(non_snake_case)]
    pub(crate) fn compute_shared(&self, values: Values, p_b: &[u8], p_a: &[u8]) -> (ProjectivePoint, ProjectivePoint) {
        // Apparently h === 1 in P256.
        let p_a = ProjectivePoint::from_encoded_point(&EncodedPoint::from_bytes(&p_a).unwrap()).unwrap();
        let p_b = ProjectivePoint::from_encoded_point(&EncodedPoint::from_bytes(&p_b).unwrap()).unwrap();
        match values {
            Values::Verifier(responder) => {
                // VERIFIER:   Z = h*y*(X - w0*M)      V = h*y*L
                let w_t_m = self.M * Scalar::from_repr(responder.w0.into()).unwrap();
                let L = ProjectivePoint::from_encoded_point(&EncodedPoint::from_bytes(&responder.L).unwrap()).unwrap();
                let Z = (p_a - w_t_m) * Scalar::from_repr(self.y.into()).unwrap();
                let V = L * Scalar::from_repr(self.y.into()).unwrap();
                (Z, V)
            }
            Values::Prover(initiator) => {
                // PROVER:     Z = h*x*(Y - w0*N)      V = h*w1*(Y - w0*N)
                let w_t_n = self.N * Scalar::from_repr(initiator.w0.into()).unwrap();
                let Z = (p_b - w_t_n) * Scalar::from_repr(self.x.into()).unwrap();
                let V = (p_b - w_t_n) * Scalar::from_repr(initiator.w1.into()).unwrap();
                (Z, V)
            }
        }
    }


    /// Alice (Prover) Bob (Verifier)
    #[allow(non_snake_case)]
    pub fn compute_confirmation(&self, tt: &Vec<u8>, p_a: &[u8], p_b: &[u8], bit_length: usize) -> S2PConfirmation {
        let K_main = hash_message(tt);
        println!("p_a = {}", hex::encode(p_a));;
        println!("p_b = {}", hex::encode(p_b));;
        println!("Hashed TT = {}", hex::encode(&K_main));

        let Ka = &K_main[..16];
        let Ke = &K_main[16..];

        let K_confirm = key_derivation(&Ka, None, b"ConfirmationKeys", bit_length);

        println!("Ka = {}", hex::encode(Ka));
        println!("Ke = {}", hex::encode(Ke));
        println!("KcAB = {}", hex::encode(&K_confirm));

        let k_c_a = &K_confirm[..16];
        let k_c_b = &K_confirm[16..];
        S2PConfirmation {
            cA: hmac(k_c_a, p_b),
            cB: hmac(k_c_b, p_a),
            Ke: Ke.try_into().unwrap(),
        }
    }
}

#[allow(non_snake_case)]
#[derive(Debug)]
pub struct S2PConfirmation {
    pub cA: [u8; CRYPTO_HASH_LEN_BYTES],
    pub cB: [u8; CRYPTO_HASH_LEN_BYTES],
    pub Ke: [u8; CRYPTO_HASH_LEN_BYTES / 2],
}

/// Generate a random value in the range of [0..p] where [p] is [ORDER] or NIST-P256.
fn generate_random() -> [u8; 32] {
    let mut bytes = random_bytes::<32>();
    let mut big = U256::from_be_slice(&bytes);
    while big >= NIST_P_256_ORDER {
        bytes = random_bytes::<32>();
        big = U256::from_be_slice(&bytes);
    }
    bytes
}

pub fn generate_bytes_from_passcode(passcode: u32) -> [u8; 4] {
    passcode.to_le_bytes()
}

pub enum Values {
    Verifier(VerifierValues),
    Prover(ValuesInitiator),
}

fn write_with_length(vec: &mut Vec<u8>, data: &[u8]) -> Result<(), MatterError> {
    vec.write_u64::<LE>(data.len() as u64)?;
    vec.extend_from_slice(data);
    Ok(())
}