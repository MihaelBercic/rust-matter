![rust tests](https://github.com/MihaelBercic/rust-matter/actions/workflows/workflow.yml/badge.svg)
![Static Badge](https://img.shields.io/badge/rust%20-%20100%25%20-%20%23EC8305)
![Static Badge](https://img.shields.io/badge/Active%20Development%20-%20%234F75FF)
![Static Badge](https://img.shields.io/badge/Since%2003/03/2023%20-%20%2308C2FF)

`in development since 03/03/2023`

<img style="border-radius: 10px" src="https://repository-images.githubusercontent.com/766485479/44dd04cb-0cda-49af-853c-0fdbcfacea51"/>

# Matter protocol implementation in Rust

<div style="text-align:center; text-transform:uppercase; font-size: 11px; font-weight: bold"> Documentation is a work in progress...</div>

## Active Development

### Interaction Protocol [Currently in development]

- [x] Attribute Read & Response
- [ ] Command Invoke & Response

### Session initialisation

- [x] Insecure session computation (PASE)
- [x] Secure session encryption

### TLV

- [x] Encoding
- [x] Decoding
- [x] Compression

### Message Protocol

- [x] Matter message builder
- [x] Protocol message builder

### Discovery

- [x] MulticastSocket
- [x] mDNS Packet Header
- [x] mDNS Packet Label compression
- [x] mDNS Packet Records
- [x] mDNS Packet building
- [x] mDNS Service advertising

### Chapter 3: Cryptographic Primitives

- [x] Deterministic Random Bit Generator (DRBG)
- [x] True Random Number Generator (TRNG)
- [x] Keyed hash - HMAC
- [x] SHA 256 hashing
- [x] Public Key cryptography (NIST P256)
- [x] Message signing
- [x] Message signature verification
- [x] ECDH
- [x] Certificate validation
- [x] SPAKE2+
