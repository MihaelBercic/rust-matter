![rust tests](https://github.com/MihaelBercic/rust-matter/actions/workflows/workflow.yml/badge.svg)
![Static Badge](https://img.shields.io/badge/rust%20-%20100%25%20-%20%23EC8305)
![Static Badge](https://img.shields.io/badge/Active%20Development%20-%20%234F75FF)
![Static Badge](https://img.shields.io/badge/Since%2003/03/2023%20-%20%2308C2FF)

<img style="border-radius: 10px" src="https://repository-images.githubusercontent.com/766485479/44dd04cb-0cda-49af-853c-0fdbcfacea51"/>

# Matter protocol implementation in Rust

<div style="text-align:center; text-transform:uppercase; font-size: 11px; font-weight: bold"> Documentation is a work in progress...</div>


## Progress
_Not all TODOs are listed due to the nature, size and complexity of the protocol._


```rust
✅ - Fully implemented
🏗️ - Currently working on
```

 **_🏗️ Interaction Protocol_**
| Status ||
| --- | ---------------------|
| ✅ | Attribute Read & Response |
| ✅ | Command Invoke & Response |
| ✅ | p256 encryption |
| ✅ | ASN.1 Encoding |
| ✅ | x509 Certification request |
| ✅ | Commissioning |
| ✅ | MDNS advertisement change after commissioning |
| 🏗️ | MDNS efficiency improvements
| 🏗️ | Efficiency oriented rewrite

---

**_✅ Session initialisation_**
| Status ||
| --- | ---------------------|
| ✅ | Insecure session computation (PASE) |
| ✅ | Secure session encryption |

---

**_✅ TLV_**
| Status ||
| --- | ---------------------|
| ✅ | Encoding |
| ✅ | Decoding |
| ✅ | Compression |

---

**_✅ Message Protocol_**
| Status ||
| --- | ---------------------|
| ✅ | Matter message builder |
| ✅ | Protocol message builder |

---

**_✅ Discovery_**
| Status ||
| --- | ---------------------|
| ✅ | MulticastSocket |
| ✅ | mDNS Packet Header |
| ✅ | mDNS Packet Label compression |
| ✅ | mDNS Packet Records |
| ✅ | mDNS Packet building |
| ✅ | mDNS Service advertising |

---

**_✅ Cryptographic Primitives_**
| Status ||
| --- | ---------------------|
| ✅ | **SPAKE2+** _this was time consuming_ |
| ✅ | Deterministic Random Bit Generator (DRBG) |
| ✅ | True Random Number Generator (TRNG) |
| ✅ | Keyed hash - HMAC |
| ✅ | SHA 256 hashing |
| ✅ | Public Key cryptography (NIST P256) |
| ✅ | Message signing |
| ✅ | Message signature verification |
| ✅ | ECDH |
| ✅ | Certificate validation |
