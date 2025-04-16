# Suite25519 Module

## Features

* **Key Pairs:** Generate Ed25519 key pairs for signing/verification.
* **Key Conversion:** Automatically handles conversions between Ed25519 and X25519 for ECIES.
* **Digital Signatures:** Sign messages using Ed25519 (EdDSA).
* **Signature Verification:** Verify Ed25519 signatures.
* **Encryption (ECIES):** Encrypt messages for a recipient using ECIES (Elliptic Curve Integrated Encryption Scheme) based on X25519, HKDF-SHA256, and AES-SIV for authenticated encryption.
* **Decryption (ECIES):** Decrypt messages encrypted with a corresponding public key.
* **Combined Operations:** Easily sign-then-encrypt and decrypt-then-verify messages.
* **Serialization:** Uses CBOR for efficient binary payload encoding. Helper methods provided for Base64 key export/import.
* **Isomorphic:** Runs in both Node.js (v16+) and modern browsers supporting Web Crypto API and standard TextEncoder/TextDecoder, atob/btoa.

## Installation

Install the package and its CBOR dependency using npm:

```bash
npm install suite25519