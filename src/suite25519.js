import {
  ed25519,
  x25519,
  edwardsToMontgomeryPub,
  edwardsToMontgomeryPriv,
} from "@noble/curves/ed25519";
import { ripemd160 } from "@noble/hashes/ripemd160";
import { sha256 } from "@noble/hashes/sha256";
import { hkdf } from "@noble/hashes/hkdf";
import { bytesToHex } from "@noble/hashes/utils"; // Only import what exists
import { siv } from "@noble/ciphers/aes";
import { randomBytes } from "@noble/ciphers/webcrypto";
import { decode, encode } from "cbor-x"; // Assuming cbor2 is browser-compatible like cbor-x

// --- Helper Functions ---

/**
 * Encodes a Uint8Array into a Base64 string.
 * Uses 'btoa' which is available in browsers and Node.js >= 16.
 * @param {Uint8Array} bytes - The bytes to encode.
 * @returns {string} - The Base64 encoded string.
 */
function bytesToBase64(bytes) {
  // Convert bytes to a string of characters with char codes matching byte values
  let binaryString = "";
  bytes.forEach((byte) => {
    binaryString += String.fromCharCode(byte);
  });
  // Encode the binary string
  try {
    return btoa(binaryString);
  } catch (e) {
    throw new Error(`Failed to encode bytes to base64: ${e.message}`);
  }
}

/**
 * Decodes a Base64 string into a Uint8Array.
 * Uses 'atob' which is available in browsers and Node.js >= 16.
 * @param {string} base64 - The Base64 encoded string.
 * @returns {Uint8Array} - The decoded bytes.
 */
function base64ToBytes(base64) {
  try {
    const binString = atob(base64);
    // Convert binary string characters to byte values
    return Uint8Array.from(binString, (m) => m.codePointAt(0));
  } catch (e) {
    // Handle potential errors like invalid characters in base64 string
    throw new Error(`Failed to decode base64 string: ${e.message}`);
  }
}

const assertType = (variableObj, expectedType) => {
  const [variableName, variable] = Object.entries(variableObj)[0];
  const actualType = typeof variable;
  const constructorName = variable?.constructor?.name;

  if (expectedType === "string") {
    if (actualType !== "string") {
      throw new Error(
        `${variableName} [${actualType}] is not an instance of [string].`,
      );
    }
  } else if (expectedType === "boolean") {
    if (actualType !== "boolean") {
      throw new Error(
        `${variableName} [${actualType}] is not an instance of [boolean].`,
      );
    }
  } else if (expectedType === Uint8Array) {
    if (!(variable instanceof Uint8Array)) {
      throw new Error(
        `${variableName} [${constructorName || actualType}] is not an instance of [Uint8Array].`,
      );
    }
  } else {
    // Assuming expectedType is a Class constructor
    if (!(variable instanceof expectedType)) {
      throw new Error(
        `${variableName} [${constructorName || actualType}] is not an instance of [${expectedType.name}].`,
      );
    }
  }
};

// --- ECIES Core Logic ---

// Use HKDF-SHA256 to derive AES key (32 bytes)
function deriveAesKey(sharedSecret) {
  // Salt should ideally be random per-encryption, but for simplicity using empty here.
  // Consider adding the ephemeral public key or nonce as salt/info if needed.
  // 'info' distinguishes the key's purpose.
  const info = new TextEncoder().encode("suite25519-aes-key");
  return hkdf(sha256, sharedSecret, undefined, info, 32); // Derive 32 bytes (256 bits)
}

function eciesEncrypt(receiverPublicKeyEd, messageUint8Array) {
  assertType({ receiverPublicKeyEd }, Uint8Array);
  assertType({ messageUint8Array }, Uint8Array);
  try {
    const receiverPublicKeyX = edwardsToMontgomeryPub(receiverPublicKeyEd);

    const ephemeralPrivateKeyX = x25519.utils.randomPrivateKey();
    const ephemeralPublicKeyX = x25519.getPublicKey(ephemeralPrivateKeyX);

    const sharedSecret = x25519.getSharedSecret(
      ephemeralPrivateKeyX,
      receiverPublicKeyX,
    );
    const aesKey = deriveAesKey(sharedSecret);

    // Generate a random nonce for AES-SIV
    // 16 bytes is generally recommended for SIV nonces if used as such.
    // If the second arg to siv() is *Associated Data*, 12 bytes might be fine.
    // Let's stick to 16 for safety if treating as a nonce. Check noble docs if it's AD.
    const nonce = randomBytes(12);

    // Pass nonce as associated data/nonce based on noble/ciphers convention
    // Assuming here it's used like a nonce or primary AD.
    const aes = siv(aesKey, nonce);
    const ciphertext = aes.encrypt(messageUint8Array);

    // Return components as Uint8Arrays
    return { C: ciphertext, P_e: ephemeralPublicKeyX, N: nonce };
  } catch (error) {
    throw new Error(`eciesEncrypt failed: ${error?.message}`);
  }
}

function eciesDecrypt(
  receiverPrivateKeyEd,
  ephemeralPublicKeyX,
  nonce,
  ciphertext,
) {
  assertType({ receiverPrivateKeyEd }, Uint8Array);
  assertType({ ephemeralPublicKeyX }, Uint8Array);
  assertType({ nonce }, Uint8Array);
  assertType({ ciphertext }, Uint8Array);
  try {
    const receiverPrivateKeyX = edwardsToMontgomeryPriv(receiverPrivateKeyEd);
    const sharedSecret = x25519.getSharedSecret(
      receiverPrivateKeyX,
      ephemeralPublicKeyX,
    );
    const aesKey = deriveAesKey(sharedSecret);

    const aes = siv(aesKey, nonce);
    let plaintext;
    try {
      plaintext = aes.decrypt(ciphertext);
    } catch (error) {
      // Log the specific Noble library error
      console.error("AES-SIV decryption failed:", error);
      throw new Error(
        "Decryption failed (authentication tag mismatch or other error)",
      );
    }
    return plaintext; // Returns Uint8Array
  } catch (error) {
    // Catch errors from key conversion/derivation
    throw new Error(`eciesDecrypt failed: ${error?.message}`);
  }
}

// --- Data Classes (Simplified) ---

// Base class just holds Uint8Array data
class BinaryData {
  constructor(data) {
    assertType({ data }, Uint8Array);
    this.data = data;
  }

  toBinary() {
    return this.data;
  }

  // Example: Base64 encode the raw binary data
  toBase64() {
    return bytesToBase64(this.data);
  }

  // Example: Create from Base64 encoded raw binary data
  static fromBase64(base64Data, ClassType = BinaryData) {
    assertType({ base64Data }, "string");
    try {
      const data = base64ToBytes(base64Data);
      return new ClassType(data);
    } catch (e) {
      throw new Error(
        `Failed to decode base64 for ${ClassType.name}: ${e.message}`,
      );
    }
  }
}

// Specific data types inherit but add little functionality here
// Could add validation (e.g., length checks) if needed
class Signature extends BinaryData {}

// Message class handles string conversion
export class Message extends BinaryData {
  constructor(data) {
    let binaryData;
    if (data instanceof Uint8Array) {
      binaryData = data;
    } else if (typeof data === "string") {
      binaryData = new TextEncoder().encode(data);
    } else {
      let dataType = typeof data;
      if (data && typeof data === "object") {
        dataType = data.constructor?.name || "Object";
      }
      throw new Error(
        `Invalid data type for Message constructor: Expected string or Uint8Array, got ${dataType}`,
      );
    }
    super(binaryData); // Call BinaryData constructor with Uint8Array
  }

  // Static method to create Message from random bytes
  static randomBytes(length = 32) {
    // Default length, e.g., 32 bytes
    return new Message(randomBytes(length));
  }

  // Convert internal Uint8Array data back to string (assumes UTF-8)
  toString() {
    try {
      return new TextDecoder().decode(this.data);
    } catch (e) {
      // Handle potential decoding errors if data isn't valid UTF-8
      console.error("Failed to decode message data as UTF-8:", e);
      // Return hex as fallback? Or throw?
      return bytesToHex(this.data);
    }
  }
}

// --- Key Classes ---

export class PrivateKey extends BinaryData {
  // No static objectIdentifier needed if not using old envelope logic

  // Creates a new random private key
  static randomPrivateKey() {
    return new PrivateKey(ed25519.utils.randomPrivateKey());
  }

  // Derives the corresponding public key
  get publicKey() {
    const publicKeyData = ed25519.getPublicKey(this.data);
    return new PublicKey(publicKeyData);
  }

  // Decrypts a CBOR-encoded ECIES payload
  decrypt(encryptedPayload) {
    assertType({ encryptedPayload }, Uint8Array);
    const { C, P_e, N } = decode(encryptedPayload); // Decodes CBOR to object
    // Ensure decoded components are Uint8Array before passing to eciesDecrypt
    assertType({ C }, Uint8Array);
    assertType({ P_e }, Uint8Array);
    assertType({ N }, Uint8Array);
    const plaintext = eciesDecrypt(this.data, P_e, N, C);
    return new Message(plaintext); // Return as Message object
  }

  // Signs a message (string or Uint8Array)
  sign(messageData) {
    const message =
      messageData instanceof Message ? messageData : new Message(messageData);
    const sigData = ed25519.sign(message.toBinary(), this.data);
    return new Signature(sigData); // Return Signature object
  }

  // Export raw key as Base64
  exportAsBase64() {
    return this.toBase64();
  }

  // Import from Base64 encoded raw key
  static importFromBase64(base64Key) {
    return BinaryData.fromBase64(base64Key, PrivateKey);
  }
}

export class PublicKey extends BinaryData {
  // No static objectIdentifier needed

  // Calculates RIPEMD-160 hash of the public key (often used for addresses)
  get id() {
    return bytesToHex(ripemd160(this.data));
  }

  // Verifies a signature against provided data
  verify(messageData, signature) {
    const message =
      messageData instanceof Message ? messageData : new Message(messageData);
    assertType({ signature }, Signature);

    let valid = false;
    try {
      valid = ed25519.verify(
        signature.toBinary(),
        message.toBinary(),
        this.data,
        { zip215: false },
      ); // RFC8032 / FIPS 186-5
    } catch (error) {
      // verification can throw on invalid points etc.
      console.error("Verification error:", error);
      return false; // Treat verification errors as invalid signature
    }

    if (!valid) {
      // Optional: throw new Error('Signature invalid');
      return false; // Typically return false for invalid signature
    } else {
      return true;
    }
  }

  // Encrypts data for this public key
  encrypt(messageData) {
    const message =
      messageData instanceof Message ? messageData : new Message(messageData);
    const cipherObject = eciesEncrypt(this.data, message.toBinary());
    // Return the CBOR-encoded payload directly
    return encode(cipherObject); // Returns Uint8Array
  }

  // Export raw key as Base64
  exportAsBase64() {
    return this.toBase64();
  }

  // Import from Base64 encoded raw key
  static importFromBase64(base64Key) {
    return BinaryData.fromBase64(base64Key, PublicKey);
  }
}

// --- High-Level API Functions ---

/**
 * Signs a message and returns a CBOR-encoded structure.
 * @param {string | Uint8Array | Message} plainMessage - The message to sign.
 * @param {PrivateKey} signingPrivateKey - The private key for signing.
 * @param {boolean} [includeMessage=false] - Whether to include the original message in the output.
 * @param {boolean} [includeSenderPublicKey=false] - Whether to include the sender's public key in the output.
 * @returns {Uint8Array} - CBOR-encoded signature structure.
 */
export const signMessage = (
  plainMessage,
  signingPrivateKey,
  includeMessage = false,
  includeSenderPublicKey = false,
) => {
  assertType({ signingPrivateKey }, PrivateKey);
  assertType({ includeMessage }, "boolean");
  assertType({ includeSenderPublicKey }, "boolean");

  const message =
    plainMessage instanceof Message ? plainMessage : new Message(plainMessage);
  const messageBinary = message.toBinary(); // Ensure we get Uint8Array

  const sig = ed25519.sign(messageBinary, signingPrivateKey.toBinary());

  const result = { sig }; // Always include signature

  if (includeMessage) {
    result.m = messageBinary; // Add original message (Uint8Array)
  }
  if (includeSenderPublicKey) {
    result.P = signingPrivateKey.publicKey.toBinary(); // Add public key (Uint8Array)
  }

  return encode(result); // Encode the result object, returns Uint8Array
};

/**
 * Verifies a signed message payload.
 * @param {Uint8Array} signedPayload - The CBOR-encoded signed message structure.
 * @param {PublicKey} senderPublicKey - The expected public key of the sender.
 * @returns {Uint8Array | null} - The original message (Uint8Array) if verification succeeds and message was included, null otherwise.
 * @throws {Error} If signature is invalid, public key mismatch, or decoding fails.
 */
export const verifyMessage = (signedPayload, senderPublicKey) => {
  assertType({ signedPayload }, Uint8Array);
  assertType({ senderPublicKey }, PublicKey);

  const decoded = decode(signedPayload); // Decode the CBOR payload
  const { sig, m, P } = decoded;

  // Basic structure check
  if (!sig || !(sig instanceof Uint8Array)) {
    throw new Error("Invalid signed payload: Missing or invalid signature.");
  }
  if (m !== undefined && !(m instanceof Uint8Array)) {
    throw new Error(
      'Invalid signed payload: Included message "m" is not Uint8Array.',
    );
  }
  if (P !== undefined && !(P instanceof Uint8Array)) {
    throw new Error(
      'Invalid signed payload: Included public key "P" is not Uint8Array.',
    );
  }

  // If Public Key is included in payload, verify it matches the expected one
  if (P) {
    const includedPublicKey = new PublicKey(P);
    if (includedPublicKey.id !== senderPublicKey.id) {
      throw new Error(
        "Verification failed: Included public key 'P' does not match expected senderPublicKey.",
      );
    }
  }

  // Determine the message to verify (either included 'm' or external 'plainMessage' if this function were different)
  // This version requires 'm' to be present for verification as written.
  if (m === undefined) {
    throw new Error(
      "Verification failed: Message 'm' not included in the signed payload.",
    );
    // Or adapt to accept plainMessage separately if needed: verify(sig, plainMessage, senderPublicKey)
  }

  const signature = new Signature(sig);
  const message = new Message(m); // Reconstruct Message object for verification method

  // Perform the actual verification
  if (!senderPublicKey.verify(message, signature)) {
    throw new Error("Verification failed: Invalid signature.");
  }

  // Verification successful
  return m; // Return the verified message content (Uint8Array)
};

/**
 * Encrypts a message for a recipient.
 * @param {string | Uint8Array | Message} plainMessage - The message to encrypt.
 * @param {PublicKey} recipientPublicKey - The public key of the recipient.
 * @returns {Uint8Array} - CBOR-encoded ECIES ciphertext structure {C, P_e, N}.
 */
export const encryptMessage = (plainMessage, recipientPublicKey) => {
  assertType({ recipientPublicKey }, PublicKey);

  const message =
    plainMessage instanceof Message ? plainMessage : new Message(plainMessage);
  const messageBinary = message.toBinary(); // Get Uint8Array

  const cipherObject = eciesEncrypt(
    recipientPublicKey.toBinary(),
    messageBinary,
  );

  return encode(cipherObject); // Encode the {C, P_e, N} object, returns Uint8Array
};

/**
 * Decrypts an ECIES payload.
 * @param {Uint8Array} encryptedPayload - The CBOR-encoded ECIES structure {C, P_e, N}.
 * @param {PrivateKey} recipientPrivateKey - The private key of the recipient.
 * @returns {Uint8Array} - The decrypted plaintext message (Uint8Array).
 * @throws {Error} If decryption or decoding fails.
 */
export const decryptMessage = (encryptedPayload, recipientPrivateKey) => {
  assertType({ encryptedPayload }, Uint8Array);
  assertType({ recipientPrivateKey }, PrivateKey);

  const { C, P_e, N } = decode(encryptedPayload); // Decode CBOR

  // Validate decoded types
  if (
    !(C instanceof Uint8Array) ||
    !(P_e instanceof Uint8Array) ||
    !(N instanceof Uint8Array)
  ) {
    throw new Error("Invalid encrypted payload structure after CBOR decoding.");
  }

  const messageBinary = eciesDecrypt(recipientPrivateKey.toBinary(), P_e, N, C);

  return messageBinary; // Return raw Uint8Array
};

/**
 * Signs and then encrypts a message.
 * @param {string | Uint8Array | Message} plainMessage - The message to sign and encrypt.
 * @param {PrivateKey} signingPrivateKey - The sender's private key.
 * @param {PublicKey} recipientPublicKey - The recipient's public key.
 * @param {boolean} [includeSenderPublicKey=true] - Whether to include sender's public key in the signed part. Recommended.
 * @returns {Uint8Array} - CBOR-encoded ECIES structure containing the signed message payload.
 */
export const signAndEncryptMessage = (
  plainMessage,
  signingPrivateKey,
  recipientPublicKey,
  includeSenderPublicKey = true,
) => {
  assertType({ signingPrivateKey }, PrivateKey);
  assertType({ recipientPublicKey }, PublicKey);
  assertType({ includeSenderPublicKey }, "boolean");

  // 1. Sign the message (including message and optionally public key) -> CBOR payload (Uint8Array)
  // It's generally good to include the public key here so the recipient knows who signed it.
  const signedPayload = signMessage(
    plainMessage,
    signingPrivateKey,
    true,
    includeSenderPublicKey,
  );

  // 2. Encrypt the *entire signed payload* for the recipient
  const encryptedSignedPayload = encryptMessage(
    signedPayload,
    recipientPublicKey,
  ); // encryptMessage handles CBOR encoding

  return encryptedSignedPayload; // Returns the final CBOR-encoded Uint8Array {C, P_e, N}
};

/**
 * Decrypts and then verifies a message.
 * @param {Uint8Array} encryptedSignedPayload - The CBOR-encoded ECIES payload from signAndEncryptMessage.
 * @param {PrivateKey} recipientPrivateKey - The recipient's private key (for decryption).
 * @param {PublicKey} senderPublicKey - The expected sender's public key (for verification).
 * @returns {Uint8Array} - The original, verified message plaintext (Uint8Array).
 * @throws {Error} If decryption, decoding, or verification fails.
 */
export const decryptAndVerifyMessage = (
  encryptedSignedPayload,
  recipientPrivateKey,
  senderPublicKey,
) => {
  assertType({ encryptedSignedPayload }, Uint8Array);
  assertType({ recipientPrivateKey }, PrivateKey);
  assertType({ senderPublicKey }, PublicKey);

  // 1. Decrypt the outer payload to get the inner signed payload
  const signedPayload = decryptMessage(
    encryptedSignedPayload,
    recipientPrivateKey,
  ); // Returns Uint8Array (inner CBOR)

  // 2. Verify the inner signed payload
  // verifyMessage handles CBOR decoding and signature verification
  const originalMessage = verifyMessage(signedPayload, senderPublicKey); // Returns original message Uint8Array if valid

  return originalMessage; // Return the verified original message
};
