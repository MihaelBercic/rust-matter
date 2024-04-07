use std::ops::Rem;

use num_bigint::BigUint;
use p256::{AffinePoint, EncodedPoint, Scalar};
use p256::elliptic_curve::generic_array::GenericArray;
use p256::elliptic_curve::PrimeField;
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};

use crate::crypto::{kdf, random_bytes};
use crate::crypto::constants::{CRYPTO_GROUP_SIZE_BYTES, CRYPTO_PUBLIC_KEY_SIZE_BYTES};

#[allow(non_upper_case_globals)]
// const M: &str = "02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f";
const BYTES_M: [u8; 33] = [0x2, 0x88, 0x6e, 0x2f, 0x97, 0xac, 0xe4, 0x6e, 0x55, 0xba, 0x9d, 0xd7, 0x24, 0x25, 0x79, 0xf2, 0x99, 0x3b, 0x64, 0xe1, 0x6e, 0xf3, 0xdc, 0xab, 0x95, 0xaf, 0xd4, 0x97, 0x33, 0x3d, 0x8f, 0xa1, 0x2f];

// const N: &str = "03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49";
const BYTES_N: [u8; 33] = [0x3, 0xd8, 0xbb, 0xd6, 0xc6, 0x39, 0xc6, 0x29, 0x37, 0xb0, 0x4d, 0x99, 0x7f, 0x38, 0xc3, 0x77, 0x7, 0x19, 0xc6, 0x29, 0xd7, 0x1, 0x4d, 0x49, 0xa2, 0x4b, 0x4f, 0x98, 0xba, 0xa1, 0x29, 0x2b, 0x49];
const NIST_P_256_ORDER: [u8; 32] = [0xff, 0xff, 0xff, 0xff, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];

const CRYPTO_W_SIZE_BYTES: usize = CRYPTO_GROUP_SIZE_BYTES + 8;
const CRYPTO_W_SIZE_BITS: usize = CRYPTO_W_SIZE_BYTES * 8;


#[allow(non_snake_case)]
pub struct Spake2P {
    w0: [u8; CRYPTO_GROUP_SIZE_BYTES],
    w1: [u8; CRYPTO_GROUP_SIZE_BYTES],
    L: [u8; CRYPTO_PUBLIC_KEY_SIZE_BYTES],
    pA: [u8; CRYPTO_PUBLIC_KEY_SIZE_BYTES],
    pB: [u8; CRYPTO_PUBLIC_KEY_SIZE_BYTES],
    M: BigUint,
    N: BigUint,
    x: BigUint,
    y: BigUint,
    X: BigUint,
    Y: BigUint,
    P: BigUint,
}

impl Spake2P {
    pub fn new() -> Spake2P {
        return Self {
            w0: [0u8; CRYPTO_GROUP_SIZE_BYTES],
            w1: [0u8; CRYPTO_GROUP_SIZE_BYTES],
            L: [0u8; CRYPTO_PUBLIC_KEY_SIZE_BYTES],
            pA: [0u8; CRYPTO_PUBLIC_KEY_SIZE_BYTES],
            pB: [0u8; CRYPTO_PUBLIC_KEY_SIZE_BYTES],
            P: BigUint::from_bytes_be(AffinePoint::GENERATOR.to_encoded_point(true).as_bytes()),
            M: BigUint::from_bytes_be(&BYTES_M),
            N: BigUint::from_bytes_be(&BYTES_N),
            x: BigUint::from(0u8),
            y: BigUint::from(0u8),
            X: BigUint::from(0u8),
            Y: BigUint::from(0u8),
        };
    }

    pub fn compute_values_initiator(&mut self, passcode: &[u8], salt: &[u8], iterations: u32) {
        /*
        byte w0s[CRYPTO_W_SIZE_BYTES] || byte w1s[CRYPTO_W_SIZE_BYTES] = (byte[2 * CRYPTO_W_SIZE_BYTES])  bit[2 * CRYPTO_W_SIZE_BITS] Crypto_PBKDF(passcode, salt, iterations, 2 * CRYPTO_W_SIZE_BITS)
        byte w0[CRYPTO_GROUP_SIZE_BYTES] = w0s mod p
        byte w1[CRYPTO_GROUP_SIZE_BYTES] = w1s mod p
        */
        let pbkdf = kdf::password_key_derivation(passcode, salt, iterations, 2 * CRYPTO_W_SIZE_BITS);
        let mut w0s = [0u8; CRYPTO_W_SIZE_BYTES];
        let mut w1s = [0u8; CRYPTO_W_SIZE_BYTES];

        w0s.copy_from_slice(&pbkdf[0..CRYPTO_W_SIZE_BYTES]);
        w1s.copy_from_slice(&pbkdf[CRYPTO_W_SIZE_BYTES..]);
        let order: BigUint = BigUint::from_bytes_be(&NIST_P_256_ORDER);

        let w0 = BigUint::from_bytes_be(&w0s).rem(&order);
        let w1 = BigUint::from_bytes_be(&w1s).rem(&order);
        self.w0.copy_from_slice(&w0.to_bytes_be()[0..CRYPTO_GROUP_SIZE_BYTES]);
        self.w1.copy_from_slice(&w1.to_bytes_be()[0..CRYPTO_GROUP_SIZE_BYTES]);
    }

    /// Passcode is serialized as **little endian** <br>
    /// 18924017 = f1:c1:20:01 <br>
    /// 00000005 = 05:00:00:00
    pub fn compute_values_verifier(&mut self) {
        let w1_scalar = Scalar::from_repr(GenericArray::from(self.w1)).unwrap();
        let length = p256::AffinePoint::GENERATOR * w1_scalar;
        self.L.copy_from_slice(length.to_encoded_point(false).as_bytes());
    }

    #[allow(non_snake_case)]
    pub fn compute_pA(&mut self) {
        // x <- [0, p-1]
        // X = x*P + w0*M
        let x = Self::generate_random();
        let w0 = BigUint::from_bytes_be(&self.w0);
        let X = x * &self.P + w0 * &self.M;
        self.X = X;
    }

    #[allow(non_snake_case)]
    pub fn compute_pB(&mut self) {
        // y <- [0, p-1]
        // Y = y*P + w0*N
        let y = Self::generate_random();
        let w0 = BigUint::from_bytes_be(&self.w0);
        let Y = y * &self.P + w0 * &self.N;
        self.Y = Y;
    }

    #[allow(non_snake_case)]
    pub fn compute_shared(&self, as_prover: bool) -> Spake2PSharedValues {
        // Apparently h === 1 in P256.
        if as_prover {
            // PROVER:     Z = h*x*(Y - w0*N)      V = h*w1*(Y - w0*N)
            let a = BigUint::from_bytes_be(&self.w0) * &self.N;
            let w1 = BigUint::from_bytes_be(&self.w1);
            let Z = &self.x * (&self.Y - &a);
            let V = w1 * (&self.Y - &a);
            return Spake2PSharedValues { Z, V };
            println!("Z: {}, B: {}", Z, V);
        } else {
            // VERIFIER:   Z = h*y*(X - w0*M)      V = h*y*L
            let a = BigUint::from_bytes_be(&self.w0) * &self.M;
            let w1 = BigUint::from_bytes_be(&self.w1);
            let L = BigUint::from_bytes_be(&self.L);
            let Z = &self.y * (&self.X - &a);
            let V = &self.y * L;
            return Spake2PSharedValues { Z, V };
        }
    }

    /// Generate a random value in the range of [0..p] where [p] is [ORDER] or NIST-P256.
    fn generate_random() -> BigUint {
        let mut bytes = random_bytes::<32>();
        let mut big = BigUint::from_bytes_be(&bytes);
        let order: BigUint = BigUint::from_bytes_be(&NIST_P_256_ORDER);
        while big >= order {
            bytes = random_bytes::<32>();
            big = BigUint::from_bytes_be(&bytes);
        }
        return big;
    }
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