//! This module provides public-key encryption and decryption functionality
//! using the `vodozemac` cryptographic library.

#![allow(missing_debug_implementations)]

use matrix_sdk_crypto::vodozemac::{base64_encode, pk_encryption};
use wasm_bindgen::prelude::*;

use super::{Curve25519PublicKey, Curve25519SecretKey};

/// A class representing an encrypted message using {@link PkEncryption}.
#[wasm_bindgen]
#[derive(Debug)]
pub struct PkMessage {
    inner: pk_encryption::Message,
}

#[wasm_bindgen]
impl PkMessage {
    /// Returns the raw ciphertext as a `Uint8Array`.
    pub fn ciphertext(&self) -> Vec<u8> {
        self.inner.ciphertext.clone()
    }

    /// Returns the raw message authentication code (MAC) as a `Uint8Array`.
    pub fn mac(&self) -> Vec<u8> {
        self.inner.mac.clone()
    }

    /// Returns the ephemeral public key used during encryption.
    #[wasm_bindgen(js_name = "ephemeralKey")]
    pub fn ephemeral_key(&self) -> Curve25519PublicKey {
        self.inner.ephemeral_key.into()
    }

    /// Constructs a `PkMessage` from its parts: ciphertext, MAC, and ephemeral
    /// key.
    #[wasm_bindgen(js_name = "fromParts")]
    pub fn from_parts(ciphertext: &[u8], mac: &[u8], ephemeral_key: &Curve25519PublicKey) -> Self {
        PkMessage {
            inner: pk_encryption::Message {
                ciphertext: ciphertext.to_vec(),
                mac: mac.to_vec(),
                ephemeral_key: ephemeral_key.inner,
            },
        }
    }

    /// Constructs a `PkMessage` from a base64-encoded representation.
    #[wasm_bindgen(js_name = "fromBase64")]
    pub fn from_base64(message: &Base64EncodedPkMessage) -> Result<Self, JsError> {
        let Base64EncodedPkMessage { ciphertext, mac, ephemeral_key } = message;

        Ok(PkMessage {
            inner: pk_encryption::Message::from_base64(ciphertext, mac, ephemeral_key)?,
        })
    }

    /// Converts the `PkMessage` into a base64-encoded representation.
    #[wasm_bindgen(js_name = "toBase64")]
    pub fn to_base64(&self) -> Base64EncodedPkMessage {
        let ciphertext = base64_encode(&self.inner.ciphertext);
        let mac = base64_encode(&self.inner.mac);
        let ephemeral_key = self.inner.ephemeral_key.to_base64();

        Base64EncodedPkMessage { ciphertext, mac, ephemeral_key }
    }
}

/// The base64-encoded variant of a {@link PkMessage}.
///
/// This can be useful if the encrypted message should be put into JSON.
#[wasm_bindgen(getter_with_clone)]
pub struct Base64EncodedPkMessage {
    /// The base64-encoded ciphertext.
    pub ciphertext: String,
    /// The base64-encoded message authentication code (MAC).
    pub mac: String,
    /// The base64-encoded ephemeral public key.
    #[wasm_bindgen(js_name = "ephemeralKey")]
    pub ephemeral_key: String,
}

#[wasm_bindgen]
impl Base64EncodedPkMessage {
    /// Creates a new base64-encoded encrypted message from its parts.
    #[wasm_bindgen(constructor)]
    pub fn new(ciphertext: &str, mac: &str, ephemeral_key: &str) -> Self {
        Self {
            ciphertext: ciphertext.to_owned(),
            mac: mac.to_owned(),
            ephemeral_key: ephemeral_key.to_owned(),
        }
    }
}

/// A class representing a public-key encryption instance.
///
/// This implements the encryption part of the
/// `m.megolm_backup.v1.curve25519-aes-sha2` algorithm described in the Matrix
/// {@link https://spec.matrix.org/v1.11/client-server-api/#backup-algorithm-mmegolm_backupv1curve25519-aes-sha2 | spec}.
///
/// @see {@link PkDecryption}
///
/// More details can be found in the official {@link https://docs.rs/vodozemac/latest/vodozemac/pk_encryption/ | vodozemac documentation}.
#[wasm_bindgen]
pub struct PkEncryption {
    inner: pk_encryption::PkEncryption,
}

#[wasm_bindgen]
impl PkEncryption {
    /// Creates a new `PkEncryption` instance from a public key.
    #[wasm_bindgen(js_name = "fromKey")]
    pub fn from_key(public_key: &Curve25519PublicKey) -> Self {
        Self { inner: pk_encryption::PkEncryption::from_key(public_key.inner) }
    }

    /// Encrypts a byte message and returns an encrypted {@link PkMessage}.
    pub fn encrypt(&self, message: &[u8]) -> Result<PkMessage, JsError> {
        Ok(PkMessage { inner: self.inner.encrypt(message)? })
    }

    /// Encrypts a string message and returns an encrypted {@link PkMessage}.
    #[wasm_bindgen(js_name = "encryptString")]
    pub fn encrypt_string(&self, message: &str) -> Result<PkMessage, JsError> {
        self.encrypt(message.as_bytes())
    }
}

/// A class representing a public-key decryption instance.
///
/// This implements the decryption part of the
/// `m.megolm_backup.v1.curve25519-aes-sha2` algorithm described in the Matrix
/// {@link https://spec.matrix.org/v1.11/client-server-api/#backup-algorithm-mmegolm_backupv1curve25519-aes-sha2 | spec}.
///
/// @see {@link PkEncryption}
///
/// More details can be found in the official {@link https://docs.rs/vodozemac/latest/vodozemac/pk_encryption/ | vodozemac documentation}.
#[wasm_bindgen]
pub struct PkDecryption {
    inner: pk_encryption::PkDecryption,
}

#[wasm_bindgen]
impl PkDecryption {
    /// Creates a new `PkDecryption` instance with a newly generated key pair.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self { inner: pk_encryption::PkDecryption::new() }
    }

    /// Creates a `PkDecryption` instance from a secret key.
    #[wasm_bindgen(js_name = "fromKey")]
    pub fn from_key(key: &Curve25519SecretKey) -> Self {
        Self { inner: pk_encryption::PkDecryption::from_key(key.inner.clone()) }
    }

    /// Returns the secret key associated with this `PkDecryption` instance.
    #[wasm_bindgen(js_name = "secretKey")]
    pub fn secret_key(&self) -> Curve25519SecretKey {
        let secret_key = self.inner.secret_key();
        let inner = secret_key.clone();

        Curve25519SecretKey { inner }
    }

    /// Returns the public key associated with this decryption instance.
    ///
    /// This can be used to construct a {@link PkEncryption} object to encrypt a
    /// message for this `PkDecryption` object.
    #[wasm_bindgen(js_name = "publicKey")]
    pub fn public_key(&self) -> Curve25519PublicKey {
        self.inner.public_key().into()
    }

    /// Decrypts an encrypted message and returns the plaintext as a UTF-8
    /// string.
    #[wasm_bindgen(js_name = "decryptString")]
    pub fn decrypt_string(&self, message: &PkMessage) -> Result<String, JsError> {
        let decrypted = self.decrypt(message)?;

        String::from_utf8(decrypted)
            .map_err(|_| JsError::new("the plaintext contains invalid unicode characters"))
    }

    /// Decrypts an encrypted message and returns the raw `Uint8Array`.
    pub fn decrypt(&self, message: &PkMessage) -> Result<Vec<u8>, JsError> {
        Ok(self.inner.decrypt(&message.inner)?)
    }
}
