// Import necessary classes and functions from your refactored library
import {
  PrivateKey,
  PublicKey,
  signMessage,
  verifyMessage,
  encryptMessage,
  decryptMessage,
  signAndEncryptMessage,
  decryptAndVerifyMessage,
  Message, // Optional: if you want to use Message.toString() in tests
} from "./src/suite25519.js";

// TextDecoder is needed to convert result Uint8Arrays back to strings for comparison
// It's global in modern Node and browsers.
// const { TextDecoder } = require('util'); // Only needed for very old Node versions

describe("Suite25519 Module Tests", () => {
  test("PrivateKey and PublicKey generation and functionality", () => {
    const privateKey = PrivateKey.randomPrivateKey();
    const publicKey = privateKey.publicKey;

    expect(privateKey).toBeDefined();
    expect(publicKey).toBeDefined();
    // Add checks for underlying data type if desired
    expect(privateKey.toBinary()).toBeInstanceOf(Uint8Array);
    expect(publicKey.toBinary()).toBeInstanceOf(Uint8Array);
  });

  test("Signing and verifying a message", () => {
    const privateKey = PrivateKey.randomPrivateKey();
    const publicKey = privateKey.publicKey;
    const message = "Hello, World!"; // Original message string

    // signMessage returns CBOR-encoded Uint8Array
    const signedPayload = signMessage(message, privateKey, true, true);
    expect(signedPayload).toBeInstanceOf(Uint8Array);

    // verifyMessage should return the original message content as Uint8Array
    const verifiedMessageBytes = verifyMessage(signedPayload, publicKey);

    // Check if the result is a Uint8Array
    expect(verifiedMessageBytes).toBeInstanceOf(Uint8Array);

    // Decode the resulting Uint8Array back to a string to compare
    const verifiedMessageText = new TextDecoder().decode(verifiedMessageBytes);
    expect(verifiedMessageText).toEqual(message);
  });

  test("Encrypting and decrypting a message", () => {
    const privateKey = PrivateKey.randomPrivateKey();
    const publicKey = privateKey.publicKey;
    const message = "Secret Message"; // Original message string

    // encryptMessage returns CBOR-encoded Uint8Array {C, P_e, N}
    const encryptedPayload = encryptMessage(message, publicKey);
    expect(encryptedPayload).toBeInstanceOf(Uint8Array);

    // decryptMessage decrypts the payload and returns the original message as Uint8Array
    const decryptedMessageBytes = decryptMessage(encryptedPayload, privateKey);

    // Check if the result is a Uint8Array
    expect(decryptedMessageBytes).toBeInstanceOf(Uint8Array);

    // Decode the resulting Uint8Array back to a string to compare
    const decryptedMessageText = new TextDecoder().decode(
      decryptedMessageBytes,
    );
    expect(decryptedMessageText).toEqual(message);
  });

  test("Signing, encrypting, and decrypting a message", () => {
    const senderPrivateKey = PrivateKey.randomPrivateKey();
    const senderPublicKey = senderPrivateKey.publicKey; // Get sender public key
    const recipientPrivateKey = PrivateKey.randomPrivateKey();
    const recipientPublicKey = recipientPrivateKey.publicKey;
    const message = "Confidential Message"; // Original message string

    // signAndEncryptMessage returns the final encrypted CBOR-encoded Uint8Array
    const encryptedSignedPayload = signAndEncryptMessage(
      message,
      senderPrivateKey,
      recipientPublicKey,
      true,
    );
    expect(encryptedSignedPayload).toBeInstanceOf(Uint8Array);

    // decryptAndVerifyMessage decrypts, verifies, and returns the original message as Uint8Array
    const decryptedVerifiedBytes = decryptAndVerifyMessage(
      encryptedSignedPayload,
      recipientPrivateKey,
      senderPublicKey,
    );

    // Check if the result is a Uint8Array
    expect(decryptedVerifiedBytes).toBeInstanceOf(Uint8Array);

    // Decode the resulting Uint8Array back to a string to compare
    const decryptedVerifiedText = new TextDecoder().decode(
      decryptedVerifiedBytes,
    );
    expect(decryptedVerifiedText).toEqual(message);
  });
});

describe("Suite25519 Module Advanced Tests", () => {
  let privateKey, publicKey;

  // Use beforeAll to generate keys once for this describe block
  beforeAll(() => {
    privateKey = PrivateKey.randomPrivateKey();
    publicKey = privateKey.publicKey;
  });

  describe("Key functionality", () => {
    test("Public key derived from private key matches expected properties", () => {
      expect(publicKey).toBeDefined();
      // PublicKey.id now uses bytesToHex, check format (40 hex chars for RIPEMD-160)
      expect(publicKey.id).toMatch(/^[0-9a-f]{40}$/i);
    });
  });

  describe("Message signing and verification", () => {
    const message = "Test message"; // Original message string

    test("Message can be signed and verified successfully", () => {
      // Sign including message and public key
      const signedPayload = signMessage(message, privateKey, true, true);
      expect(signedPayload).toBeInstanceOf(Uint8Array);

      // Verify and get back the message bytes
      const verifiedMessageBytes = verifyMessage(signedPayload, publicKey);
      expect(verifiedMessageBytes).toBeInstanceOf(Uint8Array);

      // Decode bytes to string for comparison
      const verifiedMessageText = new TextDecoder().decode(
        verifiedMessageBytes,
      );
      expect(verifiedMessageText).toEqual(message);
    });

    test("Verifying with wrong public key fails", () => {
      const wrongPublicKey = PrivateKey.randomPrivateKey().publicKey;
      // Sign including message and the correct public key ('P' field)
      const signedPayload = signMessage(message, privateKey, true, true);
      expect(signedPayload).toBeInstanceOf(Uint8Array);

      // Expect verifyMessage to throw when the 'P' field doesn't match wrongPublicKey
      expect(() => {
        verifyMessage(signedPayload, wrongPublicKey);
      }).toThrow(
        "Verification failed: Included public key 'P' does not match expected senderPublicKey.",
      ); // Match exact error message
    });

    // Optional: Test verifying with correct key but tampered signature/message
    test("Verifying with tampered signature fails", () => {
      const signedPayload = signMessage(message, privateKey, true, true);
      // Tamper the signature part within the CBOR structure (more complex to do robustly)
      // For simplicity, just assert that verification fails if signature doesn't match
      const tamperedPayload = new Uint8Array(signedPayload);
      if (tamperedPayload.length > 10) {
        // Basic check
        tamperedPayload[5] = tamperedPayload[5] ^ 0xff; // Flip some bits early on
      }
      expect(() => {
        verifyMessage(tamperedPayload, publicKey); // Should fail decoding or signature check
      }).toThrow(); // Expect *some* error (decoding or invalid signature)
    });
  });

  describe("Message encryption and decryption", () => {
    const message = "Confidential message"; // Original message string

    test("Message can be encrypted and decrypted successfully", () => {
      const encryptedPayload = encryptMessage(message, publicKey);
      expect(encryptedPayload).toBeInstanceOf(Uint8Array);

      const decryptedMessageBytes = decryptMessage(
        encryptedPayload,
        privateKey,
      );
      expect(decryptedMessageBytes).toBeInstanceOf(Uint8Array);

      const decryptedMessageText = new TextDecoder().decode(
        decryptedMessageBytes,
      );
      expect(decryptedMessageText).toEqual(message);
    });

    test("Decrypting with wrong private key fails", () => {
      const encryptedPayload = encryptMessage(message, publicKey);
      const wrongPrivateKey = PrivateKey.randomPrivateKey();

      // Expect decryptMessage to throw the specific error from eciesDecrypt's catch block
      expect(() => {
        decryptMessage(encryptedPayload, wrongPrivateKey);
      }).toThrow(
        "Decryption failed (authentication tag mismatch or other error)",
      ); // Match exact error message
    });

    // Optional: Test decrypting tampered ciphertext
    test("Decrypting tampered ciphertext fails", () => {
      const encryptedPayload = encryptMessage(message, publicKey);
      const tamperedPayload = new Uint8Array(encryptedPayload);
      if (tamperedPayload.length > 10) {
        // Basic check
        tamperedPayload[tamperedPayload.length - 5] =
          tamperedPayload[tamperedPayload.length - 5] ^ 0xff; // Flip some bits near the end (likely affecting tag)
      }
      expect(() => {
        decryptMessage(tamperedPayload, privateKey); // Should fail decryption auth tag check
      }).toThrow(
        "Decryption failed (authentication tag mismatch or other error)",
      );
    });
  });

  describe("Combined signing, encryption, and decryption", () => {
    const message = "Sensitive information"; // Original message string

    test("Message can be signed, encrypted, decrypted, and verified successfully", () => {
      // Note: Using 'publicKey' from beforeAll (derived from 'privateKey') as the sender's key
      const senderPublicKey = publicKey;
      const senderPrivateKey = privateKey;

      const recipientPrivateKey = PrivateKey.randomPrivateKey();
      const recipientPublicKey = recipientPrivateKey.publicKey;

      // Sign and encrypt
      const encryptedSignedPayload = signAndEncryptMessage(
        message,
        senderPrivateKey,
        recipientPublicKey,
        true,
      );
      expect(encryptedSignedPayload).toBeInstanceOf(Uint8Array);

      // Decrypt and verify, providing the correct recipient's private key and sender's public key
      const decryptedVerifiedBytes = decryptAndVerifyMessage(
        encryptedSignedPayload,
        recipientPrivateKey,
        senderPublicKey,
      );
      expect(decryptedVerifiedBytes).toBeInstanceOf(Uint8Array);

      // Decode the final result for comparison
      const decryptedVerifiedText = new TextDecoder().decode(
        decryptedVerifiedBytes,
      );
      expect(decryptedVerifiedText).toEqual(message);
    });

    test("Decrypt/verify fails if wrong sender public key is provided", () => {
      const senderPrivateKey = privateKey;
      const wrongSenderPublicKey = PrivateKey.randomPrivateKey().publicKey; // Different sender key

      const recipientPrivateKey = PrivateKey.randomPrivateKey();
      const recipientPublicKey = recipientPrivateKey.publicKey;

      const encryptedSignedPayload = signAndEncryptMessage(
        message,
        senderPrivateKey,
        recipientPublicKey,
        true,
      );

      // Expect decryptAndVerifyMessage to throw during the verification step
      expect(() => {
        decryptAndVerifyMessage(
          encryptedSignedPayload,
          recipientPrivateKey,
          wrongSenderPublicKey,
        );
      }).toThrow(
        "Verification failed: Included public key 'P' does not match expected senderPublicKey.",
      );
    });
  });
});
