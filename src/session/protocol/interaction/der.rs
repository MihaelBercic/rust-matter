use der::{
    asn1::{ContextSpecific, OctetString, SetOf},
    oid::ObjectIdentifier,
    Sequence, ValueOrd,
};

#[derive(Sequence)]
pub struct Pkcs7SignedData {
    pub algorithm: ObjectIdentifier,
    pub value: ContextSpecific<DerCertificationDeclaration>,
}

#[derive(Sequence, ValueOrd)]
pub struct DigestAlgorithmIdentifier {
    pub algorithm: ObjectIdentifier,
}

#[derive(Sequence)]
pub struct DerCertificationDeclaration {
    pub version: der::asn1::Int,
    pub digest_algorithm: der::asn1::SetOf<DigestAlgorithmIdentifier, 1>,
    pub encapsulated_content: EncapsulatedContentInfo,
    pub signer_info: SetOf<SignerInfo, 1>,
}

#[derive(Sequence)]
pub struct EncapsulatedContentInfo {
    pub content_type: ObjectIdentifier,
    pub content: ContextSpecific<OctetString>,
}

#[derive(Sequence, ValueOrd)]
pub struct SignerInfo {
    pub version: der::asn1::Int,
    pub subject_key_identifier: ContextSpecific<OctetString>,
    pub digest_algorithm: DigestAlgorithmIdentifier,
    pub signature_algorithm: DigestAlgorithmIdentifier,
    pub signature: OctetString,
}
