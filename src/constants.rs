///
/// @author Mihael Berčič
/// @date 21. 9. 24
///
pub const MSG_COUNTER_SYNC_REQ: u8 = 0x00;
pub const MSG_COUNTER_SYNC_RSP: u8 = 0x01;

pub const UNSPECIFIED_NODE_ID: u64 = 0x0000_0000_0000_0000;
pub const MSG_COUNTER_WINDOW_SIZE: u8 = 32;
pub const MSG_COUNTER_SYNC_REQ_JITTER: u16 = 500; // milliseconds
pub const MSG_COUNTER_SYNC_TIMEOUT: u16 = 400; // milliseconds

// TODO: Remove everything below...
// PAA without Vendor ID
// pub static TEST_CERT_PAA_NO_VID_PUBLIC_KEY: &str = "0410ef02a81a87b68121fba8d31978f807a317e50aa8a828446828914b933de8edd4a5c39c9ff71a4ce3647fd7f62653b7d2495fcba4c0f47f876880039e07204a";
// pub static TEST_CERT_PAA_NO_VID_PRIVATE_KEY: &str = "e1f073c934853baffb38bf7e8bdad7a0a674107c7769892a0ff2e06c1a2ef7a7";
// pub static TEST_CERT_PAA_NO_VID_SKID: &str = "785CE705B86B8F4E6FC793AA60CB43EA696882D5";
// pub static TEST_CERT_PAA_NO_VID_CERT: &str = // "3082019130820137a00302010202070b8fbaa8dd86ee300a06082a8648ce3d040302301a3118301606035504030c0f4d61747465722054657374205041413020170d3231303632383134323334335a180f39393939313233313233353935395a301a3118301606035504030c0f4d61747465722054657374205041413059301306072a8648ce3d020106082a8648ce3d0301070342000410ef02a81a87b68121fba8d31978f807a317e50aa8a828446828914b933de8edd4a5c39c9ff71a4ce3647fd7f62653b7d2495fcba4c0f47f876880039e07204aa366306430120603551d130101ff040830060101ff020101300e0603551d0f0101ff0404030201063// 01d0603551d0e04160414785ce705b86b8f4e6fc793aa60cb43ea696882d5301f0603551d23041830168014785ce705b86b8f4e6fc793aa60cb43ea696882d5300a06082a8648ce3d0403020348003045022100b9efdb3ea06a52ec0bf01e61daed2c2d156ddb6cf014101dab798fac05fa47e5022060061d3e35d60d9d4b0d448dad7612f7e85c582e3fc312dc18794dd373715e5d";

// PAA with Vendor ID 0xFFF1
// pub static TEST_CERT_PAA_FFF1_PRIVATE_KEY: &str = "6512caecaecfc543d60623161597162f014684c565a129b62fd28c27ab1ccc50";
// pub static TEST_CERT_PAA_FFF1_PUBLIC_KEY: &str = "04b6cb6372887f2928f5bac81aa9d93ae2431cada9d79e242f65177ef9ced932a28ecd03baaf6a8fca184a1a503542960d453f303f1f19421d751e8f8f1a9a9b75";
// pub static TEST_CERT_PAA_FFF1_SKID: &str = "6AFD22771F511FECBF1641976710DCDC31A1717E";
// pub static TEST_CERT_PAA_FFF1_CERT: &str = // "308201bd30820164a00302010202084ea8e83182d41c1c300a06082a8648ce3d04030230303118301606035504030c0f4d617474657220546573742050414131143012060a2b0601040182a27c02010c04464646313020170d3231303632383134323334335a180f39393939313233313233353935395a30303118301606035504030c0f4d617474657220546573742050414131143012060a2b0601040182a27c02010c04464646313059301306072a8648ce3d020106082a8648ce3d03010703420004b6cb6372887f2928f5bac81aa9d93ae2431cada9d79e242f65177ef9ced932a28ecd03baaf6a8fca184a1a503542960d453f303f1f19421d751e8f8// f1a9a9b75a366306430120603551d130101ff040830060101ff020101300e0603551d0f0101ff040403020106301d0603551d0e041604146afd22771f511fecbf1641976710dcdc31a1717e301f0603551d230418301680146afd22771f511fecbf1641976710dcdc31a1717e300a06082a8648ce3d0403020347003044022050aa8002f4d932a9a00538f65368ad0fffc8efbbc9beb7da569835cf9aa7510e022023bac8fe0f23e75445b65339081a47994929c72aaf0a1548d40d034d514b25de";

/*
 This is the private key from Appendix F of the Matter 1.1 Core Specification.
 The specification specifies it in PEM format:

 -----BEGIN EC PRIVATE KEY-----
MHcCAQEEIK7zSEEW6UgexXvgRy30G/SZBk5QJK2GnspeiJgC1IB1oAoGCCqGSM49
AwEHoUQDQgAEPDmJIkUrVcrzicJb0bykZWlSzLkOiGkkmthHRlMBTL+V1oeWXgNr
UhxRA35rjO3vyh60QEZpT6CIgu7WUZ3sug==
-----END EC PRIVATE KEY-----
//
// You can extract the key using openssl:
//
// openssl asn1parse -in key.txt
 */
// pub static TEST_CMS_SIGNER_PRIVATE_KEY: &str = "AEF3484116E9481EC57BE0472DF41BF499064E5024AD869ECA5E889802D48075";
// pub static TEST_CMS_SIGNER_CERT_PUBLIC_KEY: &str = "043c398922452b55caf389c25bd1bca4656952ccb90e8869249ad8474653014cbf95d687965e036b521c51037e6b8cedefca1eb44046694fa08882eed6519decba";

// You can extract the subject key identifier from the certificate in the same
// section.  The x509 command is best for that:
//
// openssl x509 -in cert.txt -text
//
// Look for the line under "X509v3 Subject Key Identifier:"
// pub static TEST_CMS_SIGNER_SUBJECT_KEY_IDENTIFIER: &str = "62FA823359ACFAA9963E1CFA140ADDF504F37160";
