# Suite25519 Module

[![npm version](https://img.shields.io/npm/v/@leachain%2fsuite25519.svg)](https://www.npmjs.com/package/@leachain/suite25519)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
**Suite25519** is a modern, cryptographic library built upon the highly-regarded [@noble/ciphers](https://github.com/paulmillr/noble-ciphers), [@noble/curves](https://github.com/paulmillr/noble-curves), and [@noble/hashes](https://github.com/paulmillr/noble-hashes), using [cbor-x](https://github.com/kriszyp/cbor-x) for CBOR serialization. It provides a straightforward API for essential cryptographic operations using secure and efficient algorithms, developed as part of the **LEA ([getlea.org](https://getlea.org))** RWA crypto project.

## Features

- **Key Pairs:** Generate Ed25519 key pairs for signing/verification.
- **Key Conversion:** Automatically handles conversions between Ed25519 and X25519 for ECIES.
- **Digital Signatures:** Sign messages using Ed25519 (EdDSA).
- **Signature Verification:** Verify Ed25519 signatures.
- **Encryption (ECIES):** Encrypt messages for a recipient using ECIES (Elliptic Curve Integrated Encryption Scheme) based on X25519, HKDF-SHA256, and AES-SIV for authenticated encryption.
- **Decryption (ECIES):** Decrypt messages encrypted with a corresponding public key.
- **Combined Operations:** Easily sign-then-encrypt and decrypt-then-verify messages.
- **Serialization:** Uses CBOR for efficient binary payload encoding. Helper methods provided for Base64 key export/import.
- **Isomorphic:** Runs in both Node.js (v16+) and modern browsers supporting Web Crypto API and standard TextEncoder/TextDecoder, atob/btoa.

## Installation

Install the package and its CBOR dependency using npm:

```bash
npm install @leachain/suite25519
```
