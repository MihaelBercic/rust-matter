# Abstract Matter protocol implementation in Rust

![example workflow](https://github.com/MihaelBercic/rust-matter/actions/workflows/rust.yml/badge.svg)

Documentation is a work in progress...

### Chapter 4: Secure channel (currently working on)

- [ ] Discovery
    - [x] MulticastSocket
    - [x] mDNS Packet Header
    - [x] mDNS Packet Label compression
    - [x] mDNS Packet Records
    - [ ] mDNS Packet building
    - [ ] mDNS Service advertising

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
