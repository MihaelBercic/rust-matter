mod crypto;

#[cfg(test)]
mod tests {
    use crate::crypto;
    use ccm::aead::{generic_array::GenericArray, AeadInPlace, KeyInit};
    use ccm::consts::U10;
    use ccm::consts::U13;

    use ccm::Ccm;

    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::Signature;
    use p256::ecdsa::VerifyingKey;

    use p256::EncodedPoint;

    #[test]
    fn crypto_hash_test_sha_256() {
        let sample = b"mihael";
        let hash = crypto::hash_message(sample);
        let hex = hash.map(|x| format!("{:02x}", x)).join("");
        assert_eq!(
            hex,
            "a1ec7aff7a3ce85b3784176861b4995fe092eea0f417443d4ba77ae96a9f812e"
        );
    }

    #[test]
    fn crypto_hmac_test() {
        let sample_key = b"my secret and secure key";
        let sample_input_message = b"input message";
        let hmac = crypto::hmac(sample_key, sample_input_message);
        let hex = hex::encode(hmac);
        assert_eq!(
            hex,
            "97d2a569059bbcd8ead4444ff99071f4c01d005bcefe0d3567e1be628e5fdcd9"
        )
    }

    #[test]
    fn crypto_hmac_verify() {
        let sample_key = b"my secret and secure key";
        let sample_input_message = b"input message";
        let x = hex::decode("97d2a569059bbcd8ead4444ff99071f4c01d005bcefe0d3567e1be628e5fdcd9")
            .unwrap();
        let hmac = crypto::verify_hmac(sample_key, sample_input_message, &x);
        hmac.expect("Verification was not successful.")
    }

    #[test]
    fn generate_key_pair() {
        let _key_pair = crypto::generate_key_pair();
    }

    #[test]
    fn sign_message() {
        let signing_key = crypto::generate_key_pair();
        let message = b"Test";
        let _signed = crypto::sign_message(&signing_key.private_key, message);
    }

    #[test]
    fn verify_signed_message() {
        let public_key_encoded = hex::decode("044f85bb78121be98ce0644cb9ae2e97d86d24bf962acabecdfa26e15f425fa0dbcafb3b8c65f5bc1f14af6e176b46bf20a58058f69d2f6d05ce91f4c44e16c5f8").unwrap();
        let message = b"Test";
        let public_key = EncodedPoint::from_bytes(&public_key_encoded).unwrap();
        let verifying_key = VerifyingKey::from_encoded_point(&public_key).unwrap();
        let signature = hex::decode("7d639959c1a701326cb6827f10b59dca871d4f5f7d80f1c898eb6d85ac37999376afc3b4e22bd7724730cf1648f8dc974d1c5df8f94380f43fbe6414b3677a77").unwrap();
        let decoded_signature = Signature::from_slice(&signature).unwrap();
        let _ = verifying_key.verify(message, &decoded_signature).is_ok();
    }

    #[test]
    fn ecdh_shared_secret() {
        let bob = crypto::ecc_generate_key_pair();
        let alice = crypto::ecc_generate_key_pair();

        let bob_public_encoded = EncodedPoint::from(bob.public_key);
        let alice_public_encoded = EncodedPoint::from(alice.public_key);

        let shared_bob = crypto::ecdh(bob.private_key, alice_public_encoded.as_ref());
        let shared_alice = crypto::ecdh(alice.private_key, bob_public_encoded.as_ref());
        assert_eq!(shared_bob, shared_alice);
    }

    #[test]
    fn test_ccm() {
        let key = hex::decode("D7828D13B2B0BDC325A76236DF93CC6B").expect("Issue decoding HEX!");
        let nonce = hex::decode("2F1DBD38CE3EDA7C23F04DD650").expect("Issue decoding HEX!");

        type Cipher = Ccm<aes::Aes128, U10, U13>;
        let key = GenericArray::from_slice(&key);
        let nonce = GenericArray::from_slice(&nonce);
        let c = Cipher::new(key);

        let mut buf1 = [1; core::u16::MAX as usize];
        let res = c.encrypt_in_place_detached(nonce, &[], &mut buf1);
        assert!(res.is_ok());

        let mut buf2 = [1; core::u16::MAX as usize + 1];
        let res = c.encrypt_in_place_detached(nonce, &[], &mut buf2);
        assert!(res.is_err());
    }
}
