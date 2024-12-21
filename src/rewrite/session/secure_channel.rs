use byteorder::{WriteBytesExt, LE};
use ccm::aead::Payload;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use std::io::Cursor;

use crate::{
    crypto::{
        self,
        constants::{CRYPTO_PUBLIC_KEY_SIZE_BYTES, CRYPTO_SESSION_KEYS_INFO, CRYPTO_SYMMETRIC_KEY_LENGTH_BITS, CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES},
        hash_message,
        kdf::key_derivation,
        random_bytes,
        spake::Spake2P,
    },
    log_debug, log_error,
    rewrite::{
        device::{Device, START_TIME},
        enums::SessionOrigin,
        protocol_message::{ProtocolMessageBuilder, SecureChannelGeneralCode, SecureStatusProtocolCode},
        session::{interaction_model::clusters::operational_credentials::matter_certificate::MatterCertificate, setup::CaseSessionSetup},
        ProtocolID, ProtocolMessage, SecureChannelProtocolOpcode,
    },
    tlv::{
        element_type::ElementType,
        structs::{PBKDFParamRequest, PBKDFParamResponse, Pake1, Pake2, Pake3, SessionParameter, StatusReport},
        tag::Tag,
        tag_control::TagControl,
        tag_number::TagNumber,
        tlv::Tlv,
    },
    utils::{bail_generic, bail_tlv, bail_transport, transport_error, MatterError},
};

use self::crypto::constants::{CRYPTO_AEAD_MIC_LENGTH_BYTES, CRYPTO_GROUP_SIZE_BYTES, CRYPTO_HASH_LEN_BYTES};

use super::{enums::MatterDestinationID, Session};

pub(crate) fn process_secure(peer_id: u64, protocol_message: ProtocolMessage, session: &mut Session, device: &mut Device) -> Result<Vec<ProtocolMessageBuilder>, MatterError> {
    let opcode = SecureChannelProtocolOpcode::from(protocol_message.opcode);
    match opcode {
        SecureChannelProtocolOpcode::StatusReport => {
            let status_report = StatusReport::try_from(protocol_message)?;
            bail_transport!("{:?}", status_report)
        }
        SecureChannelProtocolOpcode::MRPStandaloneAcknowledgement => {
            // TODO: Remove from retransmission...
            bail_generic!("Nothing to do about this...");
        }
        _ => (),
    }

    let Some(session_setup) = &mut session.session_setup else {
        todo!("Figure out status reporting...")
    };
    let tlv = Tlv::try_from_cursor(&mut Cursor::new(&protocol_message.payload))?;
    let exchange_id = protocol_message.exchange_id;
    let details = &mut device.details;
    let builder: Result<ProtocolMessageBuilder, MatterError> = match opcode {
        SecureChannelProtocolOpcode::PBKDFParamRequest => {
            let request = PBKDFParamRequest::try_from(tlv)?;
            let response = PBKDFParamResponse::build_for(&request)?;
            if let Some(param_set) = &response.pbkdf_parameters {
                session_setup.salt = param_set.salt;
                session_setup.iterations = param_set.iterations;
            }
            session_setup.peer_session_id = request.initiator_session_id;
            session_setup.session_id = response.session_id;

            let payload = Tlv::from(response).to_bytes();
            session_setup.add_to_context(&protocol_message.payload);
            session_setup.add_to_context(&payload);
            Ok(ProtocolMessageBuilder::new().set_opcode(SecureChannelProtocolOpcode::PBKDFParamResponse as u8).set_payload(&payload))
        }
        SecureChannelProtocolOpcode::PASEPake1 => {
            let salt = &session_setup.salt;
            let iterations = session_setup.iterations;
            let pake_1 = Pake1::try_from(tlv)?;
            let s2p = Spake2P::new();
            let prover = Spake2P::compute_prover(20202021, salt, iterations);
            let verifier = Spake2P::compute_verifier(20202021, salt, iterations);
            let p_b: [u8; CRYPTO_PUBLIC_KEY_SIZE_BYTES] = s2p.compute_public_verifier(&verifier.w0)?.to_encoded_point(false).as_bytes().try_into().unwrap();
            let context = hash_message(&session_setup.context);
            let transcript = s2p.compute_transcript(&context, &[], &[], crate::crypto::spake::values::Values::SpakeVerifier(verifier), &pake_1.p_a, &p_b);
            let confirmation = s2p.compute_confirmation_values(&transcript, &pake_1.p_a, &p_b, 256);
            let pake_2 = Pake2 { p_b, c_b: confirmation.cB };
            let pake_tlv: Tlv = pake_2.into();
            let payload = pake_tlv.to_bytes();
            session_setup.p_a = Some(pake_1.p_a);
            session_setup.p_b = Some(p_b);
            session_setup.confirmation = Some(confirmation);
            Ok(ProtocolMessageBuilder::new().set_payload(&payload).set_opcode(SecureChannelProtocolOpcode::PASEPake2 as u8))
        }
        SecureChannelProtocolOpcode::PASEPake3 => {
            let pake_3 = Pake3::try_from(tlv)?;
            let Some(confirmation) = &session_setup.confirmation else {
                return Err(transport_error("No confirmation present..."));
            };
            let is_okay = confirmation.c_a == pake_3.c_a;
            let (general_code, protocol_code) = if is_okay {
                (SecureChannelGeneralCode::Success, SecureStatusProtocolCode::SessionEstablishmentSuccess)
            } else {
                (SecureChannelGeneralCode::Failure, SecureStatusProtocolCode::InvalidParameter)
            };
            let status_report = StatusReport::new(general_code, ProtocolID::ProtocolSecureChannel, protocol_code);
            if is_okay {
                let kdf = key_derivation(&confirmation.k_e, None, &CRYPTO_SESSION_KEYS_INFO, CRYPTO_SYMMETRIC_KEY_LENGTH_BITS * 3);
                let length = CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES;
                let prover_key: [u8; CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES] = kdf[..length].try_into().unwrap();
                let verifier_key: [u8; CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES] = kdf[length..2 * length].try_into().unwrap();
                let attestation_challenge: [u8; CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES] = kdf[2 * length..].try_into().unwrap();
                let session_id = session_setup.session_id;
                session.session_origin = SessionOrigin::Pase;
                session.peer_session_id = session_setup.peer_session_id;
                session.session_id = session_id;
                session.prover_key = prover_key;
                session.verifier_key = verifier_key;
                session.attestation_challenge = attestation_challenge;
                session.timestamp = START_TIME.elapsed()?.as_secs();
                session.peer_node_id = MatterDestinationID::Node(peer_id);
                session.session_setup = None;
            }
            Ok(ProtocolMessageBuilder::new()
                .set_opcode(SecureChannelProtocolOpcode::StatusReport as u8)
                .set_payload(&status_report.to_bytes()))
        }
        SecureChannelProtocolOpcode::CASESigma1 => {
            let sigma_bytes = tlv.clone().to_bytes();
            let sigma = Sigma1::try_from(tlv).unwrap();
            // log_info!("We have sigma: {:?}", sigma);

            let response = 'block: {
                for (index, noc) in details.nocs.iter().enumerate() {
                    let fabric = details.fabrics.get(index).unwrap();
                    let cert = details.trusted_root_certificates.get(index).unwrap();
                    let cert = MatterCertificate::try_from(&cert[..]).unwrap();
                    let root_public_key = cert.ec_public_key;
                    let key_set = details.group_keys.get(index).unwrap();
                    let compressed_fabric = details.compressed_fabric_ids.get(index).unwrap();
                    let ipk = key_derivation(&key_set.epoch_key, Some(&compressed_fabric[..]), b"GroupKey v1.0", CRYPTO_SYMMETRIC_KEY_LENGTH_BITS);
                    let candidate_destination_id = compute_destination_id(&root_public_key, fabric.fabric_id, fabric.node_id, &sigma.initiator_random, &ipk);

                    if candidate_destination_id == sigma.destination_id {
                        log_debug!("IPK: {}", hex::encode(&ipk));

                        //log_debug!("Found our destination Candidate ID! {}", hex::encode(candidate_destination_id));
                        let noc = details.nocs.get(index).unwrap();
                        //log_info!("NOC: {}", hex::encode(&noc.noc));
                        if let Some(icac) = &noc.icac {
                            //log_info!("ICAC: {}", hex::encode(icac));
                        }

                        session.peer_session_id = sigma.initiator_session_id;
                        session.fabric_index = (index + 1) as u64;
                        session.resumption_id = random_bytes::<16>(); // TODO: make random?
                        session.local_node_id = fabric.node_id;

                        let ephemeral_key_pair = crypto::generate_ephemeral_pair();
                        let eph_public_key = ephemeral_key_pair.public_key();

                        // https://github.com/adafruit/CircuitMatter/blob/main/circuitmatter/session.py#L611C5-L613C10
                        let shared_secret = crypto::ecdh(ephemeral_key_pair, &sigma.initiator_eph_public_key);
                        session.shared_secret = Some(shared_secret);

                        let tbs = Sigma2TbsData {
                            responder_noc: noc.noc.clone(),
                            responder_icac: noc.icac.clone(),
                            responder_eph_public_key: eph_public_key.to_encoded_point(false).to_bytes().to_vec().try_into().unwrap(),
                            initiator_eph_public_key: sigma.initiator_eph_public_key,
                        };

                        let tbe = Sigma2TbeData {
                            responder_noc: noc.noc.clone(),
                            responder_icac: noc.icac.clone(),
                            resumption_id: session.resumption_id,
                            signature: crypto::sign_message(&noc.private_key, &Tlv::try_from(tbs).unwrap().to_bytes()),
                        };

                        let mut salt: Vec<u8> = vec![];
                        let random = random_bytes::<32>();
                        let mut case_context = sigma_bytes.clone();
                        salt.extend_from_slice(&ipk);
                        salt.extend_from_slice(&random);
                        salt.extend_from_slice(&eph_public_key.to_sec1_bytes());
                        salt.extend_from_slice(&hash_message(&case_context));

                        //log_info!("My salt: {}", hex::encode(&salt));

                        let s2k = key_derivation(&session.shared_secret.unwrap(), Some(&salt), b"Sigma2", CRYPTO_SYMMETRIC_KEY_LENGTH_BITS);
                        log_debug!("SR2K: {}", hex::encode(&s2k));

                        let tbe_tlv = Tlv::try_from(tbe).unwrap();
                        //log_info!("Not yet encrypted: {}", hex::encode(&tbe_tlv.clone().to_bytes()));

                        let encrypted = crypto::symmetric::encrypt(&s2k, Payload { msg: &tbe_tlv.to_bytes(), aad: &[] }, b"NCASE_Sigma2N").unwrap();
                        //log_info!("Encrypted: {}", hex::encode(&encrypted.clone()));
                        //log_info!(
                        //    "Decrypted: {}",
                        //    hex::encode(decrypt(&s2k, Payload { msg: &encrypted, aad: &[] }, b"NCASE_Sigma2N").unwrap())
                        //);
                        let sigma2 = Sigma2 {
                            responder_random: random.to_vec(),
                            responder_session_id: 6969, //session.session_id,
                            responder_eph_public_key: eph_public_key.to_sec1_bytes().to_vec().try_into().unwrap(),
                            encrypted_2: encrypted,
                            responder_session_params: sigma.initiator_session_params.clone(),
                        };

                        let sigma2 = Tlv::try_from(sigma2).unwrap();
                        // log_error!("Sigma 2 as hex: {}", hex::encode(sigma2.clone().to_bytes()));

                        case_context.extend_from_slice(&sigma2.clone().to_bytes());
                        session.case_setup = Some(CaseSessionSetup { context: case_context, ipk });
                        break 'block Ok(ProtocolMessageBuilder::new().set_opcode(SecureChannelProtocolOpcode::CASESigma2 as u8).set_payload(&sigma2.to_bytes()));
                    }
                }
                Err(transport_error("msg"))
            }?;
            Ok(response)
        }
        SecureChannelProtocolOpcode::CASESigma3 => {
            let Some(case_setup) = &mut session.case_setup else { bail_generic!("No CASE_SETUP set.") };

            let bytes = tlv.clone().to_bytes();
            let sigma3 = Sigma3::try_from(tlv).unwrap();
            let mut salt = case_setup.ipk.clone();
            salt.extend_from_slice(&hash_message(&case_setup.context));
            let s3k = key_derivation(&session.shared_secret.unwrap(), Some(&salt), b"Sigma3", CRYPTO_SYMMETRIC_KEY_LENGTH_BITS);
            let decrypted = crypto::symmetric::decrypt(&s3k, Payload { msg: &sigma3.encrypted, aad: &[] }, b"NCASE_Sigma3N").unwrap();

            // TODO verify...
            let tlv = Tlv::try_from_cursor(&mut Cursor::new(&decrypted)).unwrap();
            let tbe = Sigma3Tbe::try_from(tlv).unwrap();

            let peer_noc = tbe.initiator_noc;
            let peer_noc = MatterCertificate::try_from(&peer_noc[..]).unwrap();
            session.peer_node_id = MatterDestinationID::Node(peer_noc.subject.matter_node_id);

            case_setup.context.extend_from_slice(&bytes);

            let mut salt = vec![];
            salt.extend_from_slice(&case_setup.ipk);
            salt.extend_from_slice(&hash_message(&case_setup.context));

            //log_info!("Salt: {}", hex::encode(&salt));
            //log_info!("Shared Secret: {}", hex::encode(&session.shared_secret.unwrap()));

            let kdf = key_derivation(&session.shared_secret.unwrap(), Some(&salt), b"SessionKeys", 3 * CRYPTO_SYMMETRIC_KEY_LENGTH_BITS);

            log_debug!("kdf: {}", hex::encode(&kdf));

            let length = CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES;
            let prover_key: [u8; CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES] = kdf[..length].try_into().unwrap();
            let verifier_key: [u8; CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES] = kdf[length..2 * length].try_into().unwrap();
            let attestation_challenge: [u8; CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES] = kdf[2 * length..].try_into().unwrap();
            session.prover_key = prover_key;
            session.verifier_key = verifier_key;
            session.attestation_challenge = attestation_challenge;
            session.timestamp = START_TIME.elapsed().unwrap().as_secs();
            // secure_session_context.r2i = AESCCM(
            //     secure_session_context.r2i_key,
            //     tag_length=crypto.AEAD_MIC_LENGTH_BYTES,
            // )
            //
            let status_report = StatusReport::new(
                SecureChannelGeneralCode::Success,
                ProtocolID::ProtocolSecureChannel,
                SecureStatusProtocolCode::SessionEstablishmentSuccess,
            );
            session.session_id = 6969;
            Ok(ProtocolMessageBuilder::new()
                .set_opcode(SecureChannelProtocolOpcode::StatusReport as u8)
                .set_payload(&status_report.to_bytes()))
        }
        _ => todo!("Received OPCODE: {:?}", protocol_message.opcode),
    };

    Ok(vec![builder?.set_protocol(ProtocolID::ProtocolSecureChannel).set_exchange_id(exchange_id)])
}

fn compute_destination_id(root_public_key: &[u8], fabric_id: u64, node_id: u64, initiator_random: &[u8], ipk: &[u8]) -> [u8; 32] {
    let mut message = vec![];
    message.extend_from_slice(initiator_random);
    message.extend_from_slice(root_public_key);
    message.write_u64::<LE>(fabric_id);
    message.write_u64::<LE>(node_id);
    crypto::hmac(ipk, &message)
}

#[derive(Debug)]
struct Sigma1 {
    pub initiator_random: Vec<u8>,
    pub initiator_session_id: u16,
    pub destination_id: [u8; CRYPTO_HASH_LEN_BYTES],
    pub initiator_eph_public_key: [u8; CRYPTO_PUBLIC_KEY_SIZE_BYTES],
    pub initiator_session_params: Option<SessionParameter>,
    pub resumption_id: Option<Vec<u8>>,
    pub initiator_resume_mic: Option<[u8; CRYPTO_AEAD_MIC_LENGTH_BYTES]>,
}

impl TryFrom<Tlv> for Sigma1 {
    type Error = MatterError;

    fn try_from(value: Tlv) -> Result<Self, Self::Error> {
        let mut sigma = Self {
            initiator_random: vec![],
            initiator_session_id: 0,
            destination_id: [0; CRYPTO_HASH_LEN_BYTES],
            initiator_eph_public_key: [0; CRYPTO_PUBLIC_KEY_SIZE_BYTES],
            initiator_session_params: None,
            resumption_id: None,
            initiator_resume_mic: None,
        };

        let ElementType::Structure(children) = value.control.element_type else {
            bail_tlv!("Incorrect Tlv structure.")
        };

        for child in children {
            let Some(TagNumber::Short(tag)) = child.tag.tag_number else {
                bail_tlv!("Incorrect tag encoding.")
            };
            let element_type = child.control.element_type;
            match tag {
                1 => sigma.initiator_random = element_type.into_octet_string()?,
                2 => sigma.initiator_session_id = element_type.into_u16()?,
                3 => sigma.destination_id = element_type.into_octet_string()?.try_into()?,
                4 => sigma.initiator_eph_public_key = element_type.into_octet_string()?.try_into()?,
                5 => sigma.initiator_session_params = Some(SessionParameter::try_from(Tlv::simple(element_type))?),
                6 => sigma.resumption_id = Some(element_type.into_octet_string()?),
                7 => sigma.initiator_resume_mic = Some(element_type.into_octet_string()?.try_into()?),
                _ => bail_tlv!("The tag {} is not expected", tag),
            }
        }
        Ok(sigma)
    }
}

#[derive(Debug)]
struct Sigma2TbsData {
    pub responder_noc: Vec<u8>,
    pub responder_icac: Option<Vec<u8>>,
    pub responder_eph_public_key: [u8; CRYPTO_PUBLIC_KEY_SIZE_BYTES],
    pub initiator_eph_public_key: [u8; CRYPTO_PUBLIC_KEY_SIZE_BYTES],
}

#[derive(Debug)]
struct Sigma2TbeData {
    pub responder_noc: Vec<u8>,
    pub responder_icac: Option<Vec<u8>>,
    pub signature: [u8; CRYPTO_GROUP_SIZE_BYTES * 2],
    pub resumption_id: [u8; 16],
}

#[derive(Debug)]
struct Sigma2 {
    pub responder_random: Vec<u8>,
    pub responder_session_id: u16,
    pub responder_eph_public_key: [u8; CRYPTO_PUBLIC_KEY_SIZE_BYTES],
    pub encrypted_2: Vec<u8>,
    pub responder_session_params: Option<SessionParameter>,
}

impl TryFrom<Sigma2TbeData> for Tlv {
    type Error = MatterError;

    fn try_from(value: Sigma2TbeData) -> Result<Self, Self::Error> {
        let mut children = vec![Tlv::new(value.responder_noc.into(), TagControl::ContextSpecific8, Tag::short(1))];
        if let Some(icac) = value.responder_icac {
            children.push(Tlv::new(icac.into(), TagControl::ContextSpecific8, Tag::short(2)));
        };
        children.extend_from_slice(&[
            Tlv::new(value.signature.into(), TagControl::ContextSpecific8, Tag::short(3)),
            Tlv::new(value.resumption_id.into(), TagControl::ContextSpecific8, Tag::short(4)),
        ]);
        Ok(Tlv::simple(ElementType::Structure(children)))
    }
}

impl TryFrom<Sigma2> for Tlv {
    type Error = MatterError;

    fn try_from(value: Sigma2) -> Result<Self, Self::Error> {
        let mut children = vec![
            Tlv::new(value.responder_random.into(), TagControl::ContextSpecific8, Tag::short(1)),
            Tlv::new(value.responder_session_id.into(), TagControl::ContextSpecific8, Tag::short(2)),
            Tlv::new(value.responder_eph_public_key.into(), TagControl::ContextSpecific8, Tag::short(3)),
            Tlv::new(value.encrypted_2.into(), TagControl::ContextSpecific8, Tag::short(4)),
        ];
        if let Some(params) = value.responder_session_params {
            let mut tlv: Tlv = params.into();
            tlv.tag.tag_number = Some(TagNumber::Short(5));
            tlv.control.tag_control = TagControl::ContextSpecific8;
            children.push(tlv);
        };
        Ok(Tlv::simple(ElementType::Structure(children)))
    }
}

impl TryFrom<Sigma2TbsData> for Tlv {
    type Error = MatterError;

    fn try_from(value: Sigma2TbsData) -> Result<Self, Self::Error> {
        let mut children = vec![Tlv::new(value.responder_noc.into(), TagControl::ContextSpecific8, Tag::short(1))];
        if let Some(icac) = value.responder_icac {
            children.push(Tlv::new(icac.into(), TagControl::ContextSpecific8, Tag::short(2)));
        };
        children.extend_from_slice(&[
            Tlv::new(value.responder_eph_public_key.into(), TagControl::ContextSpecific8, Tag::short(3)),
            Tlv::new(value.initiator_eph_public_key.into(), TagControl::ContextSpecific8, Tag::short(4)),
        ]);

        Ok(Tlv::simple(ElementType::Structure(children)))
    }
}

pub struct Sigma3Tbs {
    pub initiator_noc: Vec<u8>,
    pub initiator_icac: Option<Vec<u8>>,
    pub initiator_eph_public_key: Vec<u8>,
    pub responder_eph_public_key: Vec<u8>,
}

pub struct Sigma3Tbe {
    pub initiator_noc: Vec<u8>,
    pub initiator_icac: Option<Vec<u8>>,
    pub signature: Vec<u8>,
}

impl TryFrom<Tlv> for Sigma3Tbe {
    type Error = MatterError;

    fn try_from(value: Tlv) -> Result<Self, Self::Error> {
        let mut tbe = Self {
            initiator_noc: vec![],
            initiator_icac: None,
            signature: vec![],
        };

        if let ElementType::Structure(children) = value.control.element_type {
            for child in children {
                let element_type = child.control.element_type;
                if let Some(TagNumber::Short(tag)) = child.tag.tag_number {
                    match tag {
                        1 => tbe.initiator_noc = element_type.into_octet_string()?,
                        2 => tbe.initiator_icac = Some(element_type.into_octet_string()?),
                        3 => tbe.signature = element_type.into_octet_string()?,
                        _ => bail_tlv!("Incorrect tag"),
                    }
                }
            }
        }

        Ok(tbe)
    }
}

pub struct Sigma3 {
    pub encrypted: Vec<u8>,
}

impl TryFrom<Tlv> for Sigma3 {
    type Error = MatterError;

    fn try_from(value: Tlv) -> Result<Self, Self::Error> {
        let mut sigma3 = Self { encrypted: vec![] };
        if let ElementType::Structure(children) = value.control.element_type {
            for child in children {
                let element = child.control.element_type;
                if let Some(TagNumber::Short(tag)) = child.tag.tag_number {
                    match tag {
                        1 => sigma3.encrypted = element.into_octet_string()?,
                        _ => log_error!("Tag {} should not happen.", tag),
                    }
                };
            }
        }
        Ok(sigma3)
    }
}
