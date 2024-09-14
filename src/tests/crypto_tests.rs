#![allow(dead_code)]

use crate::crypto;
use crate::crypto::spake::Spake2P;
use crate::utils::bit_subset::BitSubset;

#[cfg(test)]
mod cryptography_tests {
    use crate::crypto;
    use crate::crypto::constants::{CONTEXT_PREFIX_VALUE, CRYPTO_SYMMETRIC_KEY_LENGTH_BITS, CRYPTO_W_SIZE_BITS};
    use crate::crypto::kdf::password_key_derivation;
    use crate::crypto::spake::values::Values::SpakeVerifier;
    use crate::crypto::spake::values_initiator::ProverValues;
    use crate::crypto::spake::values_responder::VerifierValues;
    use crate::crypto::spake::Spake2P;
    use crate::crypto::{hash_message, kdf, random_bytes};
    use crate::tests::s2p_test_vectors::test_vectors::{get_test_vectors, RFC_T};
    use crate::tlv::structs::pbkdf_parameter_request::PBKDFParamRequest;
    use crate::tlv::structs::pbkdf_parameter_response::PBKDFParamResponse;
    use crate::tlv::structs::pbkdf_parameter_set::PBKDFParameterSet;
    use crate::tlv::tlv::TLV;
    use crate::utils::bit_subset::BitSubset;
    use ccm::aead::generic_array::GenericArray;
    use ccm::aead::Payload;
    use hmac::Mac;
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::Signature;
    use p256::ecdsa::VerifyingKey;
    use p256::elliptic_curve::group::GroupEncoding;
    use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
    use p256::elliptic_curve::PrimeField;
    use p256::{EncodedPoint, Scalar};

    #[test]
    fn random_bytes_generator() {
        let short_bytes = random_bytes::<10>();
        let medium_bytes = random_bytes::<32>();
        let long_bytes = random_bytes::<256>();
    }

    #[test]
    fn crypto_hash_test_sha_256() {
        let sample = b"mihael";
        let hash = crypto::hash_message(sample);
        let hex = hex::encode(hash);
        assert_eq!(hex, "a1ec7aff7a3ce85b3784176861b4995fe092eea0f417443d4ba77ae96a9f812e");
    }

    #[test]
    fn crypto_hmac() {
        let sample_key = b"my secret and communication key";
        let sample_input_message = b"input message";
        let hmac = crypto::hmac(sample_key, sample_input_message);
        let hex = hex::encode(hmac);
        crypto::verify_hmac(sample_key, sample_input_message, &hex::decode(&hex).unwrap()).expect("Verification was not successful.");

        let hmac = crypto::hmac(sample_key, b"CHIP PAKE V1 Commissioning");
        assert_eq!(hex::encode(hmac), "909754b8d240f907b5832fee1c846073ff1a42e82d42d916eda6f00fb0e5a20b")
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
    fn aes_128() {
        let key = hex::decode("D7828D13B2B0BDC325A76236DF93CC6B").expect("Issue decoding HEX!");
        let nonce = hex::decode("2F1DBD38CE3EDA7C23F04DD650").expect("Issue decoding HEX!");
        let mut taken = [0u8; 13];
        let message = b"Hello from Matter!";
        let data: [u8; 0] = [];
        taken.copy_from_slice(&nonce[0..13]);
        let encrypted = crypto::symmetric::encrypt(
            &key,
            Payload {
                msg: message,
                aad: &data,
            },
            &taken,
        )
            .expect("Issue encrypting the payload.");
        let encrypted_payload = Payload {
            msg: &encrypted[..],
            aad: &[],
        };
        let decrypted = crypto::symmetric::decrypt(&key, encrypted_payload, &taken)
            .expect("Issue decrypting the payload.");
        assert_eq!(message, decrypted.as_slice())
    }

    #[test]
    fn ctr() {
        let key = hex::decode("D7828D13B2B0BDC325A76236DF93CC6B").expect("Issue decoding HEX");
        let nonce = hex::decode("2F1DBD38CE3EDA7C23F04DD650").expect("Issue decoding HEX!");
        let mut taken = [0u8; 13];
        let mut message = b"Hello from Matter!".to_vec();
        taken.copy_from_slice(&nonce[0..13]);
        crypto::symmetric::encrypt_ctr(&key, &mut message, &taken);
        crypto::symmetric::decrypt_ctr(&key, &mut message, &taken);
    }

    #[test]
    fn kdf() {
        let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
        let kdf = kdf::key_derivation(
            &ikm[..],
            Some(&salt[..]),
            &info[..],
            3 * CRYPTO_SYMMETRIC_KEY_LENGTH_BITS,
        );
    }

    #[test]
    fn pb_kdf() {
        let password = b"password";
        let salt = b"salt";
        let n = 600_000u32;
        let expected = hex::decode("669cfe52482116fda1aa2cbe409b2f56c8e45637").unwrap();
        let key1 = password_key_derivation(password, salt, n, 160);
        assert_eq!(expected, key1);

        let salt = hex::decode("03959ebc20b8fcbda262d97f9a7a9e76e32d7a1b9c5166b6a3721e88acad8808").unwrap();
        let n = 1000;
        let expected = hex::decode("c171172da78b28f9588c4f6f5ae1a4f31aebb35d07e46fef1cf3137b49215adde80b3341e46e6c224524ef828a807a4183e0621b9160b52aa235094712b778b4d69c64b0341a65a21a34dfb52e035cce").unwrap();
        let key = password_key_derivation(password, &salt, n, CRYPTO_W_SIZE_BITS * 2);
        assert_eq!(key, expected);
    }

    #[test]
    fn rfc_spake2() {
        for rfc in RFC_T {
            let mut spake = Spake2P::new();
            // skip compute_values
            let initiator_values = ProverValues { w0: rfc.w0, w1: rfc.w1 };
            let responder_values = VerifierValues { w0: rfc.w0, L: rfc.L };
            spake.x = Scalar::from_repr(*GenericArray::from_slice(&rfc.x)).unwrap();
            spake.y = Scalar::from_repr(*GenericArray::from_slice(&rfc.y)).unwrap();
            let p_a = rfc.X;
            let p_b = rfc.Y;
            assert_eq!(&spake.compute_public_prover(&rfc.w0).unwrap().to_encoded_point(false).to_bytes().to_vec()[..], p_a);
            assert_ne!(&spake.compute_public_verifier(&rfc.w0).unwrap().to_encoded_point(false).to_bytes().to_vec()[..], p_a);
            assert_eq!(&spake.compute_public_verifier(&rfc.w0).unwrap().to_encoded_point(false).to_bytes().to_vec()[..], p_b);

            let confirmation = spake.compute_confirmation_values(&rfc.TT[..rfc.TT_len].to_vec(), &p_a, &p_b, 256);
            assert_eq!(confirmation.Ke, rfc.Ke);
            assert_eq!(confirmation.cA, rfc.cA);
            assert_eq!(confirmation.cB, rfc.cB);

            let verifier = SpakeVerifier(VerifierValues { w0: rfc.w0, L: rfc.L });
            let (z, v) = spake.compute_shared_values(&verifier, &p_a, &p_b);
            assert_eq!(z.to_encoded_point(false).to_bytes().to_vec(), rfc.Z.to_vec());
            assert_eq!(v.to_encoded_point(false).to_bytes().to_vec(), rfc.V.to_vec());
        }

        for test in get_test_vectors() {
            let mut spake = Spake2P::new();
            spake.x = Scalar::from_repr(*GenericArray::from_slice(&hex::decode(test.x).unwrap())).unwrap();
            spake.y = Scalar::from_repr(*GenericArray::from_slice(&hex::decode(test.y).unwrap())).unwrap();
            let prover_values = ProverValues {
                w0: hex::decode(test.w0).unwrap().try_into().unwrap(),
                w1: hex::decode(test.w1).unwrap().try_into().unwrap(),
            };

            let verifier_values = VerifierValues {
                w0: hex::decode(test.w0).unwrap().try_into().unwrap(),
                L: hex::decode(test.L).unwrap().try_into().unwrap(),
            };

            let p_a = spake.compute_public_prover(&prover_values.w0).unwrap().to_encoded_point(false).to_bytes().to_vec();
            let p_b = spake.compute_public_verifier(&verifier_values.w0).unwrap().to_encoded_point(false).to_bytes().to_vec();
            let test_confirm_v = hex::decode(test.K_confirmV).unwrap();
            let test_confirm_p = hex::decode(test.K_confirmP).unwrap();

            let test_shared = hex::decode(test.K_shared).unwrap();
            let test_share_p = hex::decode(test.shareP).unwrap();
            let test_share_v = hex::decode(test.shareV).unwrap();
            let context = test.Context.as_bytes();
            let id_p = test.idProver.as_bytes();
            let id_v = test.idVerifier.as_bytes();

            let (z, v) = spake.compute_shared_values(&SpakeVerifier(verifier_values.clone()), &p_a, &p_b);
            let transcript = spake.compute_transcript(context, id_p, id_v, SpakeVerifier(verifier_values), &p_a, &p_b);
            assert_eq!(z.to_encoded_point(false).as_bytes(), hex::decode(test.Z).unwrap());
            assert_eq!(v.to_encoded_point(false).as_bytes(), hex::decode(test.V).unwrap());
            assert_ne!(z.to_encoded_point(false).as_bytes(), hex::decode(test.V).unwrap());

            assert_eq!(hex::decode(test.shareP).unwrap(), p_a);
            assert_eq!(hex::decode(test.shareV).unwrap(), p_b);
            assert_eq!(p_b, hex::decode(test.shareV).unwrap());
            assert_eq!(transcript, hex::decode(test.TT).unwrap());
            assert_eq!(hash_message(&transcript), hash_message(&hex::decode(test.TT).unwrap()));
            assert_eq!(hex::decode(test.K_main).unwrap(), hash_message(&transcript));

            let confirmation = spake.compute_confirmation_values(&transcript, &p_a, &p_b, 256);
            assert_eq!(hex::decode(test.HMAC_K_confirmP_shareV).unwrap(), confirmation.cA);
            assert_ne!(hex::decode(test.HMAC_K_confirmP_shareV).unwrap(), confirmation.cB);
            assert_eq!(hex::decode(test.HMAC_K_confirmV_shareP).unwrap(), confirmation.cB);
        }
    }

    #[test]
    fn matter_spake2() {
        // // MatterJS PakeTests
        let x = hex::decode("de583b5685529de9544b92c9c8cba696751b14d65092d13458879b3bc9814b53").unwrap();
        let mut spake = Spake2P::new();
        spake.x = Scalar::from_repr(*GenericArray::from_slice(&x.clone())).unwrap();
        spake.y = Scalar::from_repr(*GenericArray::from_slice(&x.clone())).unwrap();
        let test_salt = hex::decode("03959ebc20b8fcbda262d97f9a7a9e76e32d7a1b9c5166b6a3721e88acad8808").unwrap();

        let prover = Spake2P::compute_prover(20202021, &test_salt, 1000);
        let verifier = Spake2P::compute_verifier(20202021, &test_salt, 1000);
        let pbkdf = password_key_derivation(&(20202021u32.to_le_bytes()), &test_salt, 1000, CRYPTO_W_SIZE_BITS * 2);

        assert_eq!(hex::encode(pbkdf), "c171172da78b28f9588c4f6f5ae1a4f31aebb35d07e46fef1cf3137b49215adde80b3341e46e6c224524ef828a807a4183e0621b9160b52aa235094712b778b4d69c64b0341a65a21a34dfb52e035cce");
        assert_eq!(prover.w0.to_vec(), hex::decode("00177867f1e564cc4d9f347edfc28263ee5a50f1e21177cfb9a7dc2504437ccb").unwrap());
        assert_eq!(prover.w1.to_vec(), hex::decode("0e60dc5cc1bb4b66b4547601a95bc6a1758a79f79f24f68823773fb1bb9791ca").unwrap());
        assert_eq!(verifier.L.to_vec(), hex::decode("04cf26d253cae2dd44c6954d443c7badc1e8811b8484eaae2d7bf43ec2f7e3173527877ea4a554513063036f55d2871e87e294dfdc18cd39edd6519fb4dfcde976").unwrap());
        let req = PBKDFParamRequest {
            initiator_random: hex::decode("94eab5c37d101df5ef01b2c8ecada03a7c3b0cf5e26a08feda72617f9cd391a6").unwrap(),
            initiator_session_id: 71,
            passcode_id: 0,
            has_params: false,
            initiator_session_parameters: None,
        };
        let req_bytes = Into::<TLV>::into(req).to_bytes();
        let as_tlv = hex::encode(&req_bytes);
        assert_eq!("1530012094eab5c37d101df5ef01b2c8ecada03a7c3b0cf5e26a08feda72617f9cd391a6240247240300280418", as_tlv);

        let response = PBKDFParamResponse {
            initiator_random: hex::decode("94eab5c37d101df5ef01b2c8ecada03a7c3b0cf5e26a08feda72617f9cd391a6").unwrap(),
            responder_random: hex::decode("22820a42684102fd4a92c0bad66ad1f21f3c5366f5a6d84203035e2c7caf3bae").unwrap(),
            responder_session_id: 56919,
            pbkdf_parameters: Some(PBKDFParameterSet {
                iterations: 1000,
                salt: test_salt.try_into().unwrap(),
            }),
            responder_session_params: None,
        };
        let response_bytes = Into::<TLV>::into(response).to_bytes();
        let as_tlv = hex::encode(&response_bytes);
        assert_eq!("1530012094eab5c37d101df5ef01b2c8ecada03a7c3b0cf5e26a08feda72617f9cd391a630022022820a42684102fd4a92c0bad66ad1f21f3c5366f5a6d84203035e2c7caf3bae250357de35042501e80330022003959ebc20b8fcbda262d97f9a7a9e76e32d7a1b9c5166b6a3721e88acad88081818", as_tlv);

        let p_a = hex::decode("04cce1e192a645d54a3ac9a3a3f0b334f37c03400b826b14d873124dfb96a35815f80202f05c72d055b6da24942d0a6cac18caf310100ecef23248ac8fd2ced196").unwrap();
        let p_b = spake.compute_public_verifier(&verifier.w0).unwrap().to_encoded_point(false).as_bytes().to_vec();

        assert_eq!(p_b, hex::decode("0404f972c7232cde8911de7d93e37ad752b90ad095888ac83da5f3a1d5a7eb063288ed6d358e9092a8606dac6cd6b8fdfc0b3960df85434ed60c6b6091d23da7bb").unwrap());
        let (z, v) = spake.compute_shared_values(&SpakeVerifier(verifier.clone()), &p_a, &p_b);
        assert_eq!(z.to_encoded_point(false).as_bytes(), hex::decode("04e3bb24193dd3f33a3769549d1abd19b0bdf1776a7274e35e1ecb98c318fba689bd30432374af3ff6642b9ada4ad26dac56ba6f4e679a4f8dbe0cc7f87b92799d").unwrap());
        assert_eq!(v.to_encoded_point(false).as_bytes(), hex::decode("040b8bcc14906182b7a86b23637ed62257dac82d9edc059ab216bb995023c6b17e94a7f25f16f58b175d7cd885c006be49c1551edf94579e479fb77d711cb67a5b").unwrap());
        let mut context = vec![];
        context.extend_from_slice(&CONTEXT_PREFIX_VALUE);
        context.extend_from_slice(&req_bytes);
        context.extend_from_slice(&response_bytes);
        let context = hash_message(&context);
        let transcript = spake.compute_transcript(&context, &[], &[], SpakeVerifier(verifier), &p_a, &p_b);
        let confirmation = spake.compute_confirmation_values(&transcript, &p_a, &p_b, 256);
        assert_eq!(transcript, hex::decode("200000000000000064e59c36646d7b6cf4103b78228313325c275c5aa9b5f21da9a482661f7b5e8800000000000000000000000000000000410000000000000004886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f5ff355163e43ce224e0b0e65ff02ac8e5c7be09419c785e0ca547d55a12e2d20410000000000000004d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b4907d60aa6bfade45008a636337f5168c64d9bd36034808cd564490b1e656edbe7410000000000000004cce1e192a645d54a3ac9a3a3f0b334f37c03400b826b14d873124dfb96a35815f80202f05c72d055b6da24942d0a6cac18caf310100ecef23248ac8fd2ced19641000000000000000404f972c7232cde8911de7d93e37ad752b90ad095888ac83da5f3a1d5a7eb063288ed6d358e9092a8606dac6cd6b8fdfc0b3960df85434ed60c6b6091d23da7bb410000000000000004e3bb24193dd3f33a3769549d1abd19b0bdf1776a7274e35e1ecb98c318fba689bd30432374af3ff6642b9ada4ad26dac56ba6f4e679a4f8dbe0cc7f87b92799d4100000000000000040b8bcc14906182b7a86b23637ed62257dac82d9edc059ab216bb995023c6b17e94a7f25f16f58b175d7cd885c006be49c1551edf94579e479fb77d711cb67a5b200000000000000000177867f1e564cc4d9f347edfc28263ee5a50f1e21177cfb9a7dc2504437ccb").unwrap());
        assert_eq!(confirmation.cB.to_vec(), hex::decode("d6a13c26b6c5b7c514033a0370b1830dff5116fd53de43eb2374737e9b64e4bb").unwrap());
        assert_eq!(confirmation.cA.to_vec(), hex::decode("05030c97e72b884cd0ebf0f2e6f91bfd377a8f37601bb7f633d468e289437cf7").unwrap());

        // // MatterJS Test Case 2 (PasePairingTest)
        let mut spake = Spake2P::new();
        let param_set: PBKDFParameterSet = PBKDFParameterSet { iterations: 1000, salt: hex::decode("2bb41e9d75f30c2e6b2f059410c56965717cc2bf14ed6c73a169435326a89652").unwrap().try_into().unwrap() };
        let verifier = Spake2P::compute_verifier(20202021, &param_set.salt, param_set.iterations);
        assert_eq!(hex::encode(verifier.w0), "501f85a83d1da77983ff6f0c1f742d6d98f6d0ab0ba740a38032200099c8981f");
        assert_eq!(hex::encode(verifier.L), "0463e7f225296bcd9b100e605d636a3d2c84524665cbd9b8b75e737d04bca1241486b37bdba74284de76f2db9df271d2c5bda21b8e26bc0943dcbf0542665c3aa8");
        let request = PBKDFParamRequest {
            initiator_random: hex::decode("913cc0622eca85f8d4c132c89663c5d7afa780667be930e5c11bec865479c617").unwrap(),
            initiator_session_id: 35814,
            passcode_id: 0,
            has_params: false,
            initiator_session_parameters: None,
        };
        let response = PBKDFParamResponse {
            initiator_random: hex::decode("913cc0622eca85f8d4c132c89663c5d7afa780667be930e5c11bec865479c617").unwrap(),
            responder_random: hex::decode("5682c0732b37c045ebeb416904c187a58b5341088e0172123becfb855f94a72c").unwrap(),
            responder_session_id: 17028,
            pbkdf_parameters: None,
            responder_session_params: None,
        };
        let req_tlv: TLV = request.into();
        let res_tlv: TLV = response.into();

        let mut context = vec![];
        context.extend_from_slice(&CONTEXT_PREFIX_VALUE);
        context.extend_from_slice(&req_tlv.to_bytes());
        context.extend_from_slice(&res_tlv.to_bytes());
        spake.x = Scalar::from_repr(*GenericArray::from_slice(&hex::decode("fee695b4972a4f620951010c87390d3fe1313efce399fbc2c9c7cdc04d22b4c6").unwrap())).unwrap();
        let initiator = Spake2P::compute_prover(20202021, &param_set.salt, param_set.iterations);
        assert_eq!(hex::encode(initiator.w0), hex::encode(verifier.w0));
    }
}

#[test]
fn spake2p_confirmation() {
    let spake = Spake2P::new();
    let mut tt = hex::decode("200000000000000064e59c36646d7b6cf4103b78228313325c275c5aa9b5f21da9a482661f7b5e8800000000000000000000000000000000410000000000000004886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f5ff355163e43ce224e0b0e65ff02ac8e5c7be09419c785e0ca547d55a12e2d20410000000000000004d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b4907d60aa6bfade45008a636337f5168c64d9bd36034808cd564490b1e656edbe7410000000000000004cce1e192a645d54a3ac9a3a3f0b334f37c03400b826b14d873124dfb96a35815f80202f05c72d055b6da24942d0a6cac18caf310100ecef23248ac8fd2ced19641000000000000000404f972c7232cde8911de7d93e37ad752b90ad095888ac83da5f3a1d5a7eb063288ed6d358e9092a8606dac6cd6b8fdfc0b3960df85434ed60c6b6091d23da7bb410000000000000004e3bb24193dd3f33a3769549d1abd19b0bdf1776a7274e35e1ecb98c318fba689bd30432374af3ff6642b9ada4ad26dac56ba6f4e679a4f8dbe0cc7f87b92799d4100000000000000040b8bcc14906182b7a86b23637ed62257dac82d9edc059ab216bb995023c6b17e94a7f25f16f58b175d7cd885c006be49c1551edf94579e479fb77d711cb67a5b200000000000000000177867f1e564cc4d9f347edfc28263ee5a50f1e21177cfb9a7dc2504437ccb").unwrap();
    let p_a = hex::decode("04cce1e192a645d54a3ac9a3a3f0b334f37c03400b826b14d873124dfb96a35815f80202f05c72d055b6da24942d0a6cac18caf310100ecef23248ac8fd2ced196").unwrap();
    let p_b = hex::decode("0404f972c7232cde8911de7d93e37ad752b90ad095888ac83da5f3a1d5a7eb063288ed6d358e9092a8606dac6cd6b8fdfc0b3960df85434ed60c6b6091d23da7bb").unwrap();
    let confirmation = spake.compute_confirmation_values(&tt, &p_a, &p_b, 256);
    assert_eq!(hex::encode(confirmation.cA), "05030c97e72b884cd0ebf0f2e6f91bfd377a8f37601bb7f633d468e289437cf7");
    assert_eq!(hex::encode(confirmation.cB), "d6a13c26b6c5b7c514033a0370b1830dff5116fd53de43eb2374737e9b64e4bb");

    let w0 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    spake.compute_public_verifier(&w0);
}

#[test]
fn random_bit_generator() {
    for x in (0..=128).step_by(4) {
        for _ in 0..10 {
            let int: Vec<u8> = crypto::random_bits(x);
            let mut last_bit: usize = int.len() * 8;
            'byte_loop: for byte in &int {
                for shift in (0..=7).rev() {
                    if byte.bit_subset(shift, 1) == 1 { break 'byte_loop; }
                    last_bit -= 1;
                }
            }
            assert!(last_bit <= x + 1);
        }
    }
}