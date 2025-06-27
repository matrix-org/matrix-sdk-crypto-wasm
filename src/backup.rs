//! Megolm backup types

use js_sys::JsString;
use matrix_sdk_crypto::{backups::MegolmV1BackupKey as InnerMegolmV1BackupKey, store};
use wasm_bindgen::prelude::*;

use crate::impl_from_to_inner;

/// The private part of the backup key, the one used for recovery.
#[derive(Debug, Clone)]
#[wasm_bindgen]
pub struct BackupDecryptionKey {
    pub(crate) inner: store::types::BackupDecryptionKey,
}

impl_from_to_inner!(store::types::BackupDecryptionKey => BackupDecryptionKey);

/// The public part of the backup key.
#[derive(Debug, Clone)]
#[wasm_bindgen]
pub struct MegolmV1BackupKey {
    inner: InnerMegolmV1BackupKey,
}

#[wasm_bindgen]
impl MegolmV1BackupKey {
    /// The actual base64 encoded public key.
    #[wasm_bindgen(getter, js_name = "publicKeyBase64")]
    pub fn public_key(&self) -> JsString {
        self.inner.to_base64().into()
    }

    /// Get the full name of the backup algorithm this backup key supports.
    #[wasm_bindgen(getter, js_name = "algorithm")]
    pub fn backup_algorithm(&self) -> JsString {
        self.inner.backup_algorithm().into()
    }
}

#[wasm_bindgen]
impl BackupDecryptionKey {
    /// Create a new random [`BackupDecryptionKey`].
    #[wasm_bindgen(js_name = "createRandomKey")]
    pub fn create_random_key() -> BackupDecryptionKey {
        BackupDecryptionKey {
            inner: store::types::BackupDecryptionKey::new()
                .expect("Can't gather enough randomness to create a recovery key"),
        }
    }

    /// Try to create a [`BackupDecryptionKey`] from a base 64 encoded string.
    #[wasm_bindgen(js_name = "fromBase64")]
    pub fn from_base64(key: String) -> Result<BackupDecryptionKey, JsError> {
        Ok(Self { inner: store::types::BackupDecryptionKey::from_base64(&key)? })
    }

    /// Convert the backup decryption key to a base 64 encoded string.
    #[wasm_bindgen(js_name = "toBase64")]
    pub fn to_base64(&self) -> JsString {
        self.inner.to_base64().into()
    }

    /// Get the public part of the backup key.
    #[wasm_bindgen(getter, js_name = "megolmV1PublicKey")]
    pub fn megolm_v1_public_key(&self) -> MegolmV1BackupKey {
        let public_key = self.inner.megolm_v1_public_key();

        MegolmV1BackupKey { inner: public_key }
    }

    /// Try to decrypt a message that was encrypted using the public part of the
    /// backup key.
    #[wasm_bindgen(js_name = "decryptV1")]
    pub fn decrypt_v1(
        &self,
        ephemeral_key: String,
        mac: String,
        ciphertext: String,
    ) -> Result<String, JsError> {
        self.inner.decrypt_v1(&ephemeral_key, &mac, &ciphertext).map_err(|e| e.into())
    }
}

/// Struct holding the number of room keys we have.
#[derive(Debug)]
#[wasm_bindgen]
pub struct RoomKeyCounts {
    /// The total number of room keys.
    pub total: f64,
    /// The number of backed up room keys.
    #[wasm_bindgen(js_name = "backedUp")]
    pub backed_up: f64,
}

impl From<store::types::RoomKeyCounts> for RoomKeyCounts {
    fn from(inner: store::types::RoomKeyCounts) -> Self {
        RoomKeyCounts {
            // There is no `TryFrom<usize> for f64`, so first downcast the usizes to u32, then back
            // up to f64
            total: inner.total.try_into().unwrap_or(u32::MAX).into(),
            backed_up: inner.backed_up.try_into().unwrap_or(u32::MAX).into(),
        }
    }
}

/// Stored versions of the backup keys.
#[derive(Debug)]
#[wasm_bindgen]
pub struct BackupKeys {
    /// The key used to decrypt backed up room keys
    #[wasm_bindgen(js_name = "decryptionKey", getter_with_clone)]
    pub decryption_key: Option<BackupDecryptionKey>,

    /// The version that we are using for backups.
    #[wasm_bindgen(js_name = "backupVersion", getter_with_clone)]
    pub backup_version: Option<String>,
}

#[wasm_bindgen]
impl BackupKeys {
    /// The key used to decrypt backed up room keys, encoded as base64
    ///
    /// @deprecated Use `BackupKeys.decryptionKey.toBase64()`
    #[wasm_bindgen(js_name = "decryptionKeyBase64", getter)]
    pub fn decryption_key_base64(&self) -> Option<JsString> {
        self.decryption_key.clone().map(|k| k.to_base64())
    }
}
