- Goal: writing a commissionable device in rust
- chiptool command used: `./chip-tool pairing onnetwork 0xFFAAF 20202021 --trace-to json:log --trace_decode 1
`
- chiptool output: https://gist.github.com/MihaelBercic/21df8937469b96545319164a891c8133
> the above log also contains messages I've sent from my device.
- ChipTool error: (at the bottom of the above linked gist).

Attempts to finding the fix / understand the issue:
- Using google and chiptool to generate my own DAC, PAI and cert.
- Using other' implementations certificates (CDs)
- Logging in the chiptool (you can see the logs added in the above gist with Looking for certificate...)


```
[1732122727507] [53668:18492157] [CTL] Device connection failed. Error src/credentials/CHIPCert.cpp:410: CHIP Error 0x0000004A: CA certificate not found
[1732122727507] [53668:18492157] [CTL] Error on commissioning step 'kFindOperationalForStayActive': 'src/credentials/CHIPCert.cpp:410: CHIP Error 0x0000004A: CA certificate not found'
[1732122727507] [53668:18492157] [CTL] Going from commissioning step 'kFindOperationalForStayActive' with lastErr = 'src/credentials/CHIPCert.cpp:410: CHIP Error 0x0000004A: CA certificate not found' -> 'Cleanup'
[1732122727507] [53668:18492157] [CTL] Performing next commissioning step 'Cleanup' with completion status = 'src/credentials/CHIPCert.cpp:410: CHIP Error 0x0000004A: CA certificate not found'
[1732122727507] [53668:18492157] [CTL] Successfully finished commissioning step 'Cleanup'
[1732122727507] [53668:18492157] [CTL] Commissioning complete for node ID 0x00000000000FFAAF: src/credentials/CHIPCert.cpp:410: CHIP Error 0x0000004A: CA certificate not found
[1732122727507] [53668:18492157] [TOO] Device commissioning Failure: src/credentials/CHIPCert.cpp:410: CHIP Error 0x0000004A: CA certificate not found
[1732122727507] [53668:18492152] [CTL] Shutting down the commissioner
```


My software output of Operational Credentials cluster commands:
- attestation request
- certificate chain request
- csr request


```
info      | 0 | Starting matter with the following information:
           --------------------------------------------
          |          Device Type: Light (0x0100)       |
          |          Vendor ID: 0xfff2                 |
          |          Product ID: 0x8001                |
          |          Device Name: Matter Device        |
           --------------------------------------------
info      | 2145 | ProtocolSecureChannel → PBKDFParamRequest
info      | 2317 | ProtocolSecureChannel → PASEPake1
info      | 2572 | ProtocolSecureChannel → PASEPake3
info      | 2717 | ProtocolInteractionModel → ReadRequest
info      | 2877 | ProtocolInteractionModel → StatusResponse
info      | 3022 | ProtocolInteractionModel → ReadRequest
info      | 3185 | ProtocolInteractionModel → InvokeRequest
info      | 3333 | ProtocolInteractionModel → InvokeRequest
info      | 3490 | ProtocolInteractionModel → InvokeRequest
debug     | 3639 | Invoking CertificateChainRequest command on OperationalCredentials cluster.
info      | 3640 | Responding using attestation/Chip-Test-PAI-FFF2-8001-Cert.pem (converted to DER) for PAI.
info      | 3651 | ProtocolInteractionModel → InvokeRequest
debug     | 3799 | Invoking CertificateChainRequest command on OperationalCredentials cluster.
info      | 3799 | Responding using attestation/Chip-Test-DAC-FFF2-8001-0008-Cert.pem (converted to DER) for DAC.
info      | 3811 | ProtocolInteractionModel → InvokeRequest
debug     | 3959 | Invoking AttestationRequest command on OperationalCredentials cluster.
info      | 3960 | Responding using certification-declaration/Chip-Test-CD-FFF2-8001.der as the certificate.
info      | 3960 | TLV attestation elements before attestation challenge: 153001eb3081e806092a864886f70d010702a081da3081d7020103310d300b0609608648016503040201304506092a864886f70d010701a0380436152400012501f2ff360205018018250334122c04135a494732303134315a423333303030312d32342405002406002507769824080018317c307a020103801462fa823359acfaa9963e1cfa140addf504f37160300b0609608648016503040201300a06082a8648ce3d040302044630440220092d701dc1f3fd29595ae5b7f25ac4b98617ba4344f04aaceba510f03026ba2502205b40d14beff00b1a64662b20a4ef05fb011dbc9a60f8b650bd69782c63fcf684300220c0e702dc6dd694b2a1775129cd2f5ea6b6e4d0d2b1aceaf53bc574964b9a554a2603fdc65b2818

info      | 3960 | TLV attestation elements WITH attestation challenge (ToBeSigned): 153001eb3081e806092a864886f70d010702a081da3081d7020103310d300b0609608648016503040201304506092a864886f70d010701a0380436152400012501f2ff360205018018250334122c04135a494732303134315a423333303030312d32342405002406002507769824080018317c307a020103801462fa823359acfaa9963e1cfa140addf504f37160300b0609608648016503040201300a06082a8648ce3d040302044630440220092d701dc1f3fd29595ae5b7f25ac4b98617ba4344f04aaceba510f03026ba2502205b40d14beff00b1a64662b20a4ef05fb011dbc9a60f8b650bd69782c63fcf684300220c0e702dc6dd694b2a1775129cd2f5ea6b6e4d0d2b1aceaf53bc574964b9a554a2603fdc65b2818a217a3d9ee1237ee12092a032ded7a6d

info      | 3980 | Signing TBS elements using key: attestation/Chip-Test-DAC-FFF2-8001-0008-Key.pem
info      | 3988 | Signature of TBS 7d919efb9ebccb3452edf7d6320a88cb8f1c0c287711b2f2c118c15823c8362fa899cda270d7cb9943643f97bf66346daae1b28541d68410562cbd9d2c26a9ee
info      | 3988 | TLV response AttestationResponse command data: 1531001901153001eb3081e806092a864886f70d010702a081da3081d7020103310d300b0609608648016503040201304506092a864886f70d010701a0380436152400012501f2ff360205018018250334122c04135a494732303134315a423333303030312d32342405002406002507769824080018317c307a020103801462fa823359acfaa9963e1cfa140addf504f37160300b0609608648016503040201300a06082a8648ce3d040302044630440220092d701dc1f3fd29595ae5b7f25ac4b98617ba4344f04aaceba510f03026ba2502205b40d14beff00b1a64662b20a4ef05fb011dbc9a60f8b650bd69782c63fcf684300220c0e702dc6dd694b2a1775129cd2f5ea6b6e4d0d2b1aceaf53bc574964b9a554a2603fdc65b28183001407d919efb9ebccb3452edf7d6320a88cb8f1c0c287711b2f2c118c15823c8362fa899cda270d7cb9943643f97bf66346daae1b28541d68410562cbd9d2c26a9ee18

info      | 4020 | ProtocolInteractionModel → InvokeRequest
debug     | 4142 | Invoking CSRRequest command on OperationalCredentials cluster.
info      | 4167 | CSR der hex: 3081da308181020100300e310c300a060355040a0c034353413059301306072a8648ce3d020106082a8648ce3d030107034200044fdbdba45e1bb9425a5d1aefc79305a6d80184fae31dbf2162389e768b943fe0a8ea7372bcb6e54a77343855e3e819d96c6fa867d30fd0607f781e31b2cb8af0a011300f06092a864886f70d01090e31023000300a06082a8648ce3d0403020348003045022012b38b23810e3933ded729191253cf58d9d9061fda080a638f5fc35d37a31c8e022100f5700e02efdf7f033e6428da24082744027fb3926638ce0602098bea115b2356
info      | 4167 | TBS with attestation challenge:      153001dd3081da308181020100300e310c300a060355040a0c034353413059301306072a8648ce3d020106082a8648ce3d030107034200044fdbdba45e1bb9425a5d1aefc79305a6d80184fae31dbf2162389e768b943fe0a8ea7372bcb6e54a77343855e3e819d96c6fa867d30fd0607f781e31b2cb8af0a011300f06092a864886f70d01090e31023000300a06082a8648ce3d0403020348003045022012b38b23810e3933ded729191253cf58d9d9061fda080a638f5fc35d37a31c8e022100f5700e02efdf7f033e6428da24082744027fb3926638ce0602098bea115b2356300220eb88d9fd7cd94b1d03b605cb522d9cb015d5a58650ee086317ed7f18c07ce4c418a217a3d9ee1237ee12092a032ded7a6d

info      | 4186 | Signing the TBS using attestation/Chip-Test-DAC-FFF2-8001-0008-Key.pem
info      | 4186 | Signature: d095edfbd71b2511ebe63073c51204271ac13706685f34a6e621d24a7f5c4d8cac2833e3c6c415ca06f715e1b564bdcd497b7737554c90c13051ab66a5c0034d
info      | 4205 | ProtocolInteractionModel → InvokeRequest
info      | 4352 | ProtocolInteractionModel → InvokeRequest
info      | 4717 | ProtocolSecureChannel → CASESigma1
debug     | 4810 | Found our destination Candidate ID! 7d1d763b4e8ae4925224ca336108ea5289f882d11d47a48b96456e8493b15754
info      | 4852 | ProtocolSecureChannel → StatusReport
```
