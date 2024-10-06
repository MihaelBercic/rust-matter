# Abstract Matter protocol implementation in Rust

![rust tests](https://github.com/MihaelBercic/rust-matter/actions/workflows/workflow.yml/badge.svg)
![Static Badge](https://img.shields.io/badge/in%20active%20development%20-%20lightgreen)


<div style="text-align:center; text-transform:uppercase; font-size: 11px; font-weight: bold"> Documentation is a work in progress...</div>

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