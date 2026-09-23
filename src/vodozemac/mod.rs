//! Vodozemac types.

use matrix_sdk_crypto::vodozemac::{self, base64_decode, base64_encode};
use wasm_bindgen::prelude::*;
use zeroize::{Zeroize, Zeroizing};

use crate::impl_from_to_inner;

pub mod ecies;
pub mod hpke;
pub mod pk_encryption;

/// An Ed25519 public key, used to verify digital signatures.
#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct Ed25519PublicKey {
    inner: vodozemac::Ed25519PublicKey,
}

#[wasm_bindgen]
impl Ed25519PublicKey {
    /// The number of bytes an Ed25519 public key has.
    #[wasm_bindgen(getter)]
    pub fn length(&self) -> usize {
        vodozemac::Ed25519PublicKey::LENGTH
    }

    /// Serialize an Ed25519 public key to an unpadded base64
    /// representation.
    #[wasm_bindgen(js_name = "toBase64")]
    pub fn to_base64(&self) -> String {
        self.inner.to_base64()
    }
}

impl_from_to_inner!(vodozemac::Ed25519PublicKey => Ed25519PublicKey);

/// An Ed25519 digital signature, can be used to verify the
/// authenticity of a message.
#[wasm_bindgen]
#[derive(Debug)]
pub struct Ed25519Signature {
    pub(crate) inner: vodozemac::Ed25519Signature,
}

impl_from_to_inner!(vodozemac::Ed25519Signature => Ed25519Signature);

#[wasm_bindgen]
impl Ed25519Signature {
    /// Try to create an Ed25519 signature from an unpadded base64
    /// representation.
    #[wasm_bindgen(constructor)]
    pub fn new(signature: String) -> Result<Ed25519Signature, JsError> {
        Ok(Self { inner: vodozemac::Ed25519Signature::from_base64(signature.as_str())? })
    }

    /// Serialize a Ed25519 signature to an unpadded base64
    /// representation.
    #[wasm_bindgen(js_name = "toBase64")]
    pub fn to_base64(&self) -> String {
        self.inner.to_base64()
    }
}

/// A Curve25519 public key.
#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct Curve25519PublicKey {
    pub(crate) inner: vodozemac::Curve25519PublicKey,
}

#[wasm_bindgen]
impl Curve25519PublicKey {
    /// Create a new [`Curve25519PublicKey`] from a base64 encoded string.
    #[wasm_bindgen(constructor)]
    pub fn new(key: &str) -> Result<Curve25519PublicKey, JsError> {
        let inner = vodozemac::Curve25519PublicKey::from_base64(&key)?;

        Ok(Self { inner })
    }

    /// The number of bytes a Curve25519 public key has.
    #[wasm_bindgen(getter)]
    pub fn length(&self) -> usize {
        vodozemac::Curve25519PublicKey::LENGTH
    }

    /// Serialize an Curve25519 public key to an unpadded base64
    /// representation.
    #[wasm_bindgen(js_name = "toBase64")]
    pub fn to_base64(&self) -> String {
        self.inner.to_base64()
    }
}

impl_from_to_inner!(vodozemac::Curve25519PublicKey => Curve25519PublicKey);

/// A Curve25519 secret key.
#[wasm_bindgen]
#[allow(missing_debug_implementations)]
pub struct Curve25519SecretKey {
    inner: vodozemac::Curve25519SecretKey,
}

#[wasm_bindgen]
impl Curve25519SecretKey {
    /// Generates a new random Curve25519 secret key.
    pub fn new() -> Self {
        Self { inner: vodozemac::Curve25519SecretKey::new() }
    }

    /// Creates a `Curve25519SecretKey` from a base64-encoded representation of
    /// the key.
    #[wasm_bindgen(js_name = "fromBase64")]
    pub fn from_base64(string: &str) -> Result<Self, JsError> {
        let mut key = base64_decode(&string)?;
        let result = Self::from_slice(&key);

        key.zeroize();

        result
    }

    /// Encodes the secret key into a base64 string.
    #[wasm_bindgen(js_name = "toBase64")]
    pub fn to_base64(&self) -> String {
        let mut bytes = self.inner.to_bytes();
        let string = base64_encode(bytes.as_ref());

        bytes.zeroize();

        string
    }

    /// Converts the secret key into a raw byte vector.
    #[wasm_bindgen(js_name = "toUint8Array")]
    pub fn to_vec(&self) -> Vec<u8> {
        let mut bytes = self.inner.to_bytes();
        let vec = bytes.to_vec();

        bytes.zeroize();

        vec
    }

    /// Creates a `Curve25519SecretKey` from a raw byte slice.
    #[wasm_bindgen(js_name = "fromUint8Array")]
    pub fn from_slice(slice: &[u8]) -> Result<Self, JsError> {
        let length = slice.len();

        if length == 32 {
            let mut key = Zeroizing::new([0u8; 32]);
            key.copy_from_slice(slice);

            let inner = vodozemac::Curve25519SecretKey::from_slice(&key);

            Ok(Self { inner })
        } else {
            Err(JsError::new(&format!(
                "invalid key size for a Curve25519 key, expected 32 bytes, got {length}"
            )))
        }
    }
}

impl_from_to_inner!(vodozemac::Curve25519SecretKey => Curve25519SecretKey);

/// Struct holding the two public identity keys of an account.
#[wasm_bindgen(getter_with_clone)]
#[derive(Debug)]
pub struct IdentityKeys {
    /// The Ed25519 public key, used for signing.
    pub ed25519: Ed25519PublicKey,

    /// The Curve25519 public key, used for establish shared secrets.
    pub curve25519: Curve25519PublicKey,
}

impl From<matrix_sdk_crypto::olm::IdentityKeys> for IdentityKeys {
    fn from(value: matrix_sdk_crypto::olm::IdentityKeys) -> Self {
        Self {
            ed25519: Ed25519PublicKey { inner: value.ed25519 },
            curve25519: Curve25519PublicKey { inner: value.curve25519 },
        }
    }
}

/// An enum over the different key types a device can have.
///
/// Currently devices have a curve25519 and ed25519 keypair. The keys
/// transport format is a base64 encoded string, any unknown key type
/// will be left as such a string.
#[wasm_bindgen]
#[derive(Debug)]
pub struct DeviceKey {
    inner: matrix_sdk_crypto::types::DeviceKey,
}

impl_from_to_inner!(matrix_sdk_crypto::types::DeviceKey => DeviceKey);

#[wasm_bindgen]
impl DeviceKey {
    /// Get the name of the device key.
    #[wasm_bindgen(getter)]
    pub fn name(&self) -> DeviceKeyName {
        (&self.inner).into()
    }

    /// Get the value associated to the `Curve25519` device key name.
    #[wasm_bindgen(getter)]
    pub fn curve25519(&self) -> Option<Curve25519PublicKey> {
        use matrix_sdk_crypto::types::DeviceKey::*;

        match &self.inner {
            Curve25519(key) => Some((*key).into()),
            _ => None,
        }
    }

    /// Get the value associated to the `Ed25519` device key name.
    #[wasm_bindgen(getter)]
    pub fn ed25519(&self) -> Option<Ed25519PublicKey> {
        use matrix_sdk_crypto::types::DeviceKey::*;

        match &self.inner {
            Ed25519(key) => Some((*key).into()),
            _ => None,
        }
    }

    /// Get the value associated to the `Unknown` device key name.
    #[wasm_bindgen(getter)]
    pub fn unknown(&self) -> Option<String> {
        use matrix_sdk_crypto::types::DeviceKey::*;

        match &self.inner {
            Unknown(key) => Some(key.clone()),
            _ => None,
        }
    }

    /// Convert the `DeviceKey` into a base64 encoded string.
    #[wasm_bindgen(js_name = "toBase64")]
    pub fn to_base64(&self) -> String {
        self.inner.to_base64()
    }
}

impl From<&matrix_sdk_crypto::types::DeviceKey> for DeviceKeyName {
    fn from(device_key: &matrix_sdk_crypto::types::DeviceKey) -> Self {
        use matrix_sdk_crypto::types::DeviceKey::*;

        match device_key {
            Curve25519(_) => Self::Curve25519,
            Ed25519(_) => Self::Ed25519,
            Unknown(_) => Self::Unknown,
        }
    }
}

/// An enum over the different key types a device can have.
///
/// Currently devices have a curve25519 and ed25519 keypair. The keys
/// transport format is a base64 encoded string, any unknown key type
/// will be left as such a string.
#[wasm_bindgen]
#[derive(Debug)]
pub enum DeviceKeyName {
    /// The curve25519 device key.
    Curve25519,

    /// The ed25519 device key.
    Ed25519,

    /// An unknown device key.
    Unknown,
}
