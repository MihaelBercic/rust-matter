use std::cmp::max;
use std::iter;
use std::ops::Rem;

use num_bigint::BigUint;
use p256::{AffinePoint, EncodedPoint, ProjectivePoint, Scalar};
use p256::elliptic_curve::generic_array::GenericArray;
use p256::elliptic_curve::PrimeField;
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};

use crate::crypto::{hash_message, hmac, kdf, random_bytes};
use crate::crypto::constants::{CRYPTO_GROUP_SIZE_BYTES, CRYPTO_PUBLIC_KEY_SIZE_BYTES};
use crate::crypto::kdf::key_derivation;

#[allow(non_upper_case_globals)]
// const M: &str = "02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f";
const BYTES_M: [u8; 33] = [
    0x2, 0x88, 0x6e, 0x2f, 0x97, 0xac, 0xe4, 0x6e, 0x55, 0xba, 0x9d, 0xd7, 0x24, 0x25, 0x79, 0xf2,
    0x99, 0x3b, 0x64, 0xe1, 0x6e, 0xf3, 0xdc, 0xab, 0x95, 0xaf, 0xd4, 0x97, 0x33, 0x3d, 0x8f, 0xa1,
    0x2f,
];

// "CHIP PAKE V1 Commissioning" - The usage of CHIP here is intentional and due to implementation in the SDK before the name change, should not be renamed to Matter.
const CONTEXT_PREFIX_VALUE: [u8; 26] = [
    0x43, 0x48, 0x49, 0x50, 0x20, 0x50, 0x41, 0x4b, 0x45, 0x20, 0x56, 0x31, 0x20, 0x43, 0x6f, 0x6d,
    0x6d, 0x69, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x69, 0x6e, 0x67,
];

// const N: &str = "03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49";
const BYTES_N: [u8; 33] = [
    0x3, 0xd8, 0xbb, 0xd6, 0xc6, 0x39, 0xc6, 0x29, 0x37, 0xb0, 0x4d, 0x99, 0x7f, 0x38, 0xc3, 0x77,
    0x7, 0x19, 0xc6, 0x29, 0xd7, 0x1, 0x4d, 0x49, 0xa2, 0x4b, 0x4f, 0x98, 0xba, 0xa1, 0x29, 0x2b,
    0x49,
];
const NIST_P_256_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
];

const CRYPTO_W_SIZE_BYTES: usize = CRYPTO_GROUP_SIZE_BYTES + 8;
const CRYPTO_W_SIZE_BITS: usize = CRYPTO_W_SIZE_BYTES * 8;

#[allow(non_snake_case)]
pub struct Spake2P {
    pub w0: [u8; CRYPTO_GROUP_SIZE_BYTES],
    pub w1: [u8; CRYPTO_GROUP_SIZE_BYTES],
    pub(crate) L: [u8; CRYPTO_PUBLIC_KEY_SIZE_BYTES],
    pub(crate) pA: [u8; CRYPTO_PUBLIC_KEY_SIZE_BYTES],
    pub(crate) pB: [u8; CRYPTO_PUBLIC_KEY_SIZE_BYTES],
    pub(crate) M: AffinePoint,
    pub(crate) N: AffinePoint,
    pub(crate) x: [u8; 32],
    pub(crate) y: [u8; 32],
    pub(crate) X: ProjectivePoint,
    pub(crate) Y: ProjectivePoint,
    pub(crate) Z: ProjectivePoint,
    pub(crate) V: ProjectivePoint,
}

impl Spake2P {
    pub fn new() -> Spake2P {
        return Self {
            w0: [0u8; CRYPTO_GROUP_SIZE_BYTES],
            w1: [0u8; CRYPTO_GROUP_SIZE_BYTES],
            L: [0u8; CRYPTO_PUBLIC_KEY_SIZE_BYTES],
            pA: [0u8; CRYPTO_PUBLIC_KEY_SIZE_BYTES],
            pB: [0u8; CRYPTO_PUBLIC_KEY_SIZE_BYTES],
            M: AffinePoint::from_encoded_point(&EncodedPoint::from_bytes(&BYTES_M).unwrap())
                .unwrap(),
            N: AffinePoint::from_encoded_point(&EncodedPoint::from_bytes(&BYTES_N).unwrap())
                .unwrap(),
            x: Self::generate_random(),
            y: Self::generate_random(),
            X: ProjectivePoint::IDENTITY,
            Y: ProjectivePoint::IDENTITY,
            Z: ProjectivePoint::IDENTITY,
            V: ProjectivePoint::IDENTITY,
        };
    }

    pub fn compute_values_initiator(&mut self, passcode: &[u8], salt: &[u8], iterations: u32) {
        /*
        byte w0s[CRYPTO_W_SIZE_BYTES] || byte w1s[CRYPTO_W_SIZE_BYTES] = (byte[2 * CRYPTO_W_SIZE_BYTES])  bit[2 * CRYPTO_W_SIZE_BITS] Crypto_PBKDF(passcode, salt, iterations, 2 * CRYPTO_W_SIZE_BITS)
        byte w0[CRYPTO_GROUP_SIZE_BYTES] = w0s mod p
        byte w1[CRYPTO_GROUP_SIZE_BYTES] = w1s mod p
        */
        let pbkdf =
            kdf::password_key_derivation(passcode, salt, iterations, 2 * CRYPTO_W_SIZE_BITS);
        let mut w0s = [0u8; CRYPTO_W_SIZE_BYTES];
        let mut w1s = [0u8; CRYPTO_W_SIZE_BYTES];

        w0s.copy_from_slice(&pbkdf[0..CRYPTO_W_SIZE_BYTES]);
        w1s.copy_from_slice(&pbkdf[CRYPTO_W_SIZE_BYTES..]);
        let order: BigUint = BigUint::from_bytes_be(&NIST_P_256_ORDER);

        let w0 = BigUint::from_bytes_be(&w0s).rem(&order);
        let w1 = BigUint::from_bytes_be(&w1s).rem(&order);
        self.w0
            .copy_from_slice(&w0.to_bytes_be()[0..CRYPTO_GROUP_SIZE_BYTES]);
        self.w1
            .copy_from_slice(&w1.to_bytes_be()[0..CRYPTO_GROUP_SIZE_BYTES]);
    }

    /// Passcode is serialized as **little endian** <br>
    /// 18924017 = f1:c1:20:01 <br>
    /// 00000005 = 05:00:00:00
    pub fn compute_values_verifier(&mut self) {
        let w1_scalar = Scalar::from_repr(GenericArray::from(self.w1)).unwrap();
        let length = p256::AffinePoint::GENERATOR * w1_scalar;
        self.L
            .copy_from_slice(length.to_encoded_point(false).as_bytes());
    }

    #[allow(non_snake_case)]
    pub fn compute_pA(&mut self) {
        // x <- [0, p-1]
        // X = x*P + w0*M
        let w_s = Scalar::from_repr(*GenericArray::from_slice(&self.w0)).unwrap();
        let x_s = Scalar::from_repr(*GenericArray::from_slice(&self.x)).unwrap();
        let X = (AffinePoint::GENERATOR * x_s) + (self.M * w_s);
        self.X = X;
    }

    #[allow(non_snake_case)]
    pub fn compute_pB(&mut self) {
        // y <- [0, p-1]
        // Y = y*P + w0*N
        let w_s = Scalar::from_repr(*GenericArray::from_slice(&self.w0)).unwrap();
        let y_s = Scalar::from_repr(*GenericArray::from_slice(&self.y)).unwrap();
        let Y = (AffinePoint::GENERATOR * y_s) + (self.N * w_s);
        self.Y = Y;
    }

    #[allow(non_snake_case)]
    pub fn compute_shared(&mut self, as_prover: bool) {
        // Apparently h === 1 in P256.
        if as_prover {
            // PROVER:     Z = h*x*(Y - w0*N)      V = h*w1*(Y - w0*N)
            let w_t_n = self.N * Scalar::from_repr(self.w0.into()).unwrap();
            let Z = (self.Y - w_t_n) * Scalar::from_repr(self.x.into()).unwrap();
            let V = (self.Y - w_t_n) * Scalar::from_repr(self.w1.into()).unwrap();
            self.Z = Z;
            self.V = V;
        } else {
            // VERIFIER:   Z = h*y*(X - w0*M)      V = h*y*L
            let w_t_m = self.M * Scalar::from_repr(self.w0.into()).unwrap();
            let L =
                ProjectivePoint::from_encoded_point(&EncodedPoint::from_bytes(&self.L).unwrap())
                    .unwrap();
            let Z = (self.X - w_t_m) * Scalar::from_repr(self.y.into()).unwrap();
            let V = L * Scalar::from_repr(self.y.into()).unwrap();
            self.Z = Z;
            self.V = V;
        }
    }

    /// Generate a random value in the range of [0..p] where [p] is [ORDER] or NIST-P256.
    fn generate_random() -> [u8; 32] {
        let mut bytes = random_bytes::<32>();
        let mut big = BigUint::from_bytes_be(&bytes);
        let order: BigUint = BigUint::from_bytes_be(&NIST_P_256_ORDER);
        while big >= order {
            bytes = random_bytes::<32>();
            big = BigUint::from_bytes_be(&bytes);
        }
        return bytes;
    }

    #[allow(unused_variables)]
    #[allow(non_snake_case)]
    pub fn compute_transcript(&self) -> Vec<u8> {
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
        let mut buffer: Vec<u8> = vec![];
        buffer.extend_from_slice(&CONTEXT_PREFIX_VALUE);
        buffer.extend_from_slice(b""); // TODO: IDK yet
        buffer.extend_from_slice(b""); // TODO: IDK yet
        let context = hash_message(&buffer).to_vec();
        let context_length = context.len().to_le_bytes().pad(PaddingMode::Left, 8, 0);
        let M_as_bytes = self.M.to_encoded_point(false).as_bytes().to_vec();
        let N_as_bytes = self.N.to_encoded_point(false).as_bytes().to_vec();
        let Z_as_bytes = self.Z.to_encoded_point(false).as_bytes().to_vec();
        let V_as_bytes = self.V.to_encoded_point(false).as_bytes().to_vec();
        let length_M = M_as_bytes.len().to_le_bytes().pad(PaddingMode::Left, 8, 0);
        let length_N = N_as_bytes.len().to_le_bytes().pad(PaddingMode::Left, 8, 0);
        let length_pA = self.pA.len().to_le_bytes().pad(PaddingMode::Left, 8, 0);
        let length_pB = self.pB.len().to_le_bytes().pad(PaddingMode::Left, 8, 0);
        let length_Z = Z_as_bytes.len().to_le_bytes().pad(PaddingMode::Left, 8, 0);
        let length_V = V_as_bytes.len().to_le_bytes().pad(PaddingMode::Left, 8, 0);
        let length_w0 = self.w0.len().to_le_bytes().pad(PaddingMode::Left, 8, 0);
        let empty = ([0u8]).pad(PaddingMode::Left, 8, 0);

        let tt = [
            context_length,
            context,
            empty.clone(),
            empty.clone(),
            length_M,
            M_as_bytes,
            length_N,
            N_as_bytes,
            length_pA,
            self.pA.to_vec(),
            length_pB,
            self.pB.to_vec(),
            length_Z,
            Z_as_bytes,
            length_V,
            V_as_bytes,
            length_w0,
            self.w0.to_vec(),
        ]
        .concat();
        return tt;
    }

    #[allow(non_snake_case)]
    pub fn compute_confirmation(&self, tt: &Vec<u8>) -> S2PConfirmation {
        let K_main = hash_message(&tt);
        let K_confirm = key_derivation(&[], &K_main, b"ConfirmationKeys", 256);
        let K_shared = key_derivation(&[], &K_main, b"SharedKey", 128);
        let mut K_shared_array = [0u8; 16];
        K_shared_array.copy_from_slice(&K_shared);
        let K_confirm_P = &K_confirm[0..16];
        let K_confirm_V = &K_confirm[16..];
        let confirm_P = hmac(&K_confirm_P, &self.pB);
        let confirm_V = hmac(&K_confirm_V, &self.pA);
        return S2PConfirmation {
            cA: confirm_P,
            cB: confirm_V,
            Ke: K_shared_array,
        };
    }
}

#[allow(non_snake_case)]
pub struct S2PConfirmation {
    cA: [u8; 32],
    cB: [u8; 32],
    Ke: [u8; 16],
}

#[derive(PartialEq, Copy, Clone, Debug)]
pub enum Spake2VerifierState {
    // Initialised - w0, L are set
    Init,
    // Pending Confirmation - Keys are derived but pending confirmation
    PendingConfirmation,
    // Confirmed
    Confirmed,
}

#[allow(non_snake_case)]
pub struct Spake2PSharedValues {
    Z: BigUint,
    V: BigUint,
}

#[derive(PartialEq, Debug)]
pub enum Spake2Mode {
    Unknown,
    Prover,
    Verifier(Spake2VerifierState),
}

pub struct Spake2PParamRequest {}

// TODO
pub struct Spake2PParamResponse {} // TODO

pub trait Extensions {
    fn pad(&self, mode: PaddingMode, size: usize, value: u8) -> Vec<u8>;
}

pub enum PaddingMode {
    Left,
    Right,
}

impl Extensions for [u8] {
    fn pad(&self, mode: PaddingMode, size: usize, value: u8) -> Vec<u8> {
        let mut vector: Vec<u8> = vec![];
        let length = self.len();
        let padding_needed = max(size - length, 0);
        let adding: Vec<u8> = iter::repeat(value).take(padding_needed).collect();
        match mode {
            PaddingMode::Left => {
                vector.extend(&adding);
                vector.extend_from_slice(&self);
            }
            PaddingMode::Right => {
                vector.extend_from_slice(&self);
                vector.extend(&adding);
            }
        }
        return vector;
    }
}
