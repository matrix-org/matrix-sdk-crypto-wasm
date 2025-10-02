//! Store types.

use std::sync::Arc;

use js_sys::Promise;
use matrix_sdk_crypto::{
    store::{DynCryptoStore, IntoCryptoStore, MemoryStore},
    types::BackupSecrets,
};
use tracing::{dispatcher, instrument::WithSubscriber};
use wasm_bindgen::prelude::*;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    encryption::EncryptionAlgorithm,
    future::future_to_promise,
    identifiers::{RoomId, UserId},
    impl_from_to_inner,
    tracing::{logger_to_dispatcher, JsLogger},
    vodozemac::Curve25519PublicKey,
};

/// A struct containing an open connection to a CryptoStore.
///
/// Opening the CryptoStore can take some time, due to the PBKDF calculation
/// involved, so if multiple operations are being done on the same store, it is
/// more efficient to open it once.
#[wasm_bindgen]
#[derive(Clone, Debug)]
pub struct StoreHandle {
    pub(crate) store: Arc<DynCryptoStore>,
}

#[wasm_bindgen]
impl StoreHandle {
    /// Open a crypto store.
    ///
    /// The created store will be based on IndexedDB if a `store_name` is
    /// provided; otherwise it will be based on a memory store and once the
    /// objects is dropped, the keys will be lost.
    ///
    /// # Arguments
    ///
    /// * `store_name` - The name that should be used to open the IndexedDB
    ///   based database. If this isn't provided, a memory-only store will be
    ///   used. *Note* the memory-only store will lose your E2EE keys when the
    ///   `StoreHandle` gets dropped.
    ///
    /// * `store_passphrase` - The passphrase that should be used to encrypt the
    ///   store, for IndexedDB-based stores
    ///
    /// * `logger` - An optional logger instance to use for writing log messages
    ///   during the open operation. An instance of `JsLogger`.
    #[wasm_bindgen(js_name = "open", unchecked_return_type = "Promise<StoreHandle>")]
    pub fn open_for_js(
        store_name: Option<String>,
        store_passphrase: Option<String>,
        logger: Option<JsLogger>,
    ) -> Promise {
        let _guard = dispatcher::set_default(&logger_to_dispatcher(logger));
        future_to_promise(async move {
            StoreHandle::open(store_name, store_passphrase).with_current_subscriber().await
        })
    }

    pub(crate) async fn open(
        store_name: Option<String>,
        store_passphrase: Option<String>,
    ) -> Result<StoreHandle, JsError> {
        let store = match store_name {
            Some(store_name) => Self::open_indexeddb(&store_name, store_passphrase).await?,

            None => {
                if store_passphrase.is_some() {
                    return Err(JsError::new(
                        "The `store_passphrase` has been set, but it has an effect only if \
                        `store_name` is set, which is not; please provide one",
                    ));
                }

                MemoryStore::new().into_crypto_store()
            }
        };

        Ok(Self { store })
    }

    async fn open_indexeddb(
        store_name: &str,
        store_passphrase: Option<String>,
    ) -> Result<Arc<DynCryptoStore>, matrix_sdk_indexeddb::IndexeddbCryptoStoreError> {
        let store = match store_passphrase {
            Some(mut store_passphrase) => {
                use zeroize::Zeroize;

                let store = matrix_sdk_indexeddb::IndexeddbCryptoStore::open_with_passphrase(
                    store_name,
                    &store_passphrase,
                )
                .await?;

                store_passphrase.zeroize();
                store
            }

            None => matrix_sdk_indexeddb::IndexeddbCryptoStore::open_with_name(store_name).await?,
        };

        Ok(store.into_crypto_store())
    }

    /// Open a crypto store based on IndexedDB, using the given key for
    /// encryption.
    ///
    /// # Arguments
    ///
    /// * `store_name` - The name that should be used to open the IndexedDB
    ///   based database.
    ///
    /// * `store_key` - The key that should be used to encrypt the store, for
    ///   IndexedDB-based stores. Must be a 32-byte array.
    ///
    /// * `logger` - An optional logger instance to use for writing log messages
    ///   during the open operation. An instance of `JsLogger`.
    #[wasm_bindgen(js_name = "openWithKey", unchecked_return_type = "Promise<StoreHandle>")]
    pub fn open_with_key(
        store_name: String,
        mut store_key: Vec<u8>,
        logger: Option<JsLogger>,
    ) -> Promise {
        let _guard = dispatcher::set_default(&logger_to_dispatcher(logger));
        future_to_promise(async move {
            let store_key_array: Zeroizing<[u8; 32]> = Zeroizing::new(
                store_key
                    .as_slice()
                    .try_into()
                    .map_err(|_| JsError::new("Expected a key of length 32"))?,
            );
            store_key.zeroize();

            let store = matrix_sdk_indexeddb::IndexeddbCryptoStore::open_with_key(
                &store_name,
                &store_key_array,
            )
            .await?;

            Ok(Self { store: store.into_crypto_store() })
        })
    }
}

impl IntoCryptoStore for StoreHandle {
    fn into_crypto_store(self) -> Arc<DynCryptoStore> {
        self.store.clone()
    }
}

/// A struct containing private cross signing keys that can be backed
/// up or uploaded to the secret store.
#[wasm_bindgen]
#[derive(Debug)]
pub struct CrossSigningKeyExport {
    pub(crate) inner: matrix_sdk_crypto::store::types::CrossSigningKeyExport,
}

impl_from_to_inner!(matrix_sdk_crypto::store::types::CrossSigningKeyExport => CrossSigningKeyExport);

#[wasm_bindgen]
impl CrossSigningKeyExport {
    /// The seed of the master key encoded as unpadded base64.
    #[wasm_bindgen(getter, js_name = "masterKey")]
    pub fn master_key(&self) -> Option<String> {
        self.inner.master_key.clone()
    }

    /// The seed of the self signing key encoded as unpadded base64.
    #[wasm_bindgen(getter, js_name = "self_signing_key")]
    pub fn self_signing_key(&self) -> Option<String> {
        self.inner.self_signing_key.clone()
    }

    /// The seed of the user signing key encoded as unpadded base64.
    #[wasm_bindgen(getter, js_name = "userSigningKey")]
    pub fn user_signing_key(&self) -> Option<String> {
        self.inner.user_signing_key.clone()
    }
}

/// Information on a room key that has been received or imported.
#[wasm_bindgen]
#[derive(Debug)]
pub struct RoomKeyInfo {
    pub(crate) inner: matrix_sdk_crypto::store::types::RoomKeyInfo,
}

impl_from_to_inner!(matrix_sdk_crypto::store::types::RoomKeyInfo => RoomKeyInfo);

#[wasm_bindgen]
impl RoomKeyInfo {
    /// The {@link EncryptionAlgorithm} that this key is used for. Will be one
    /// of the `m.megolm.*` algorithms.
    #[wasm_bindgen(getter)]
    pub fn algorithm(&self) -> EncryptionAlgorithm {
        self.inner.algorithm.clone().into()
    }

    /// The room where the key is used.
    #[wasm_bindgen(getter, js_name = "roomId")]
    pub fn room_id(&self) -> RoomId {
        self.inner.room_id.clone().into()
    }

    /// The Curve25519 key of the device which initiated the session originally.
    #[wasm_bindgen(getter, js_name = "senderKey")]
    pub fn sender_key(&self) -> Curve25519PublicKey {
        self.inner.sender_key.into()
    }

    /// The ID of the session that the key is for.
    #[wasm_bindgen(getter, js_name = "sessionId")]
    pub fn session_id(&self) -> String {
        self.inner.session_id.clone()
    }
}

/// Information on a received `m.room_key.withheld` event.
#[wasm_bindgen]
#[derive(Debug)]
pub struct RoomKeyWithheldInfo {
    pub(crate) inner: matrix_sdk_crypto::store::types::RoomKeyWithheldInfo,
}

impl_from_to_inner!(matrix_sdk_crypto::store::types::RoomKeyWithheldInfo => RoomKeyWithheldInfo);

#[wasm_bindgen]
impl RoomKeyWithheldInfo {
    /// The User ID of the sender of the withheld information.
    ///
    /// This may be the sender of an `m.room_key.withheld` event, or the sender
    /// of a shared room key bundle under MSC4268.
    #[wasm_bindgen(getter)]
    pub fn sender(&self) -> UserId {
        self.inner.withheld_event.sender.to_owned().into()
    }

    /// The encryption algorithm of the session that is being withheld.
    ///
    /// This may be from an `m.room_key.withheld` event, or from a shared room
    /// key bundle under MSC4268.
    #[wasm_bindgen(getter)]
    pub fn algorithm(&self) -> EncryptionAlgorithm {
        self.inner.withheld_event.content.algorithm().into()
    }

    /// The `code` indicating why the key was withheld, such as `m.unverified`.
    ///
    /// This may be from an `m.room_key.withheld` event (such as
    /// `m.unverified`), or from a shared room key bundle under MSC4268.
    #[wasm_bindgen(getter, js_name = "withheldCode")]
    pub fn withheld_code(&self) -> String {
        self.inner.withheld_event.content.withheld_code().as_str().to_owned()
    }

    /// The room ID of the session that is being withheld.
    #[wasm_bindgen(getter, js_name = "roomId")]
    pub fn room_id(&self) -> RoomId {
        self.inner.room_id.to_owned().into()
    }

    /// The session ID of the session that is being withheld.
    #[wasm_bindgen(getter, js_name = "sessionId")]
    pub fn session_id(&self) -> String {
        self.inner.session_id.to_owned()
    }
}

/// Struct containing the bundle of secrets to fully activate a new device for
/// end-to-end encryption.
#[derive(Debug)]
#[wasm_bindgen]
pub struct SecretsBundle {
    pub(super) inner: matrix_sdk_crypto::types::SecretsBundle,
}

/// The backup-specific parts of a secrets bundle.
#[derive(Debug)]
#[wasm_bindgen(getter_with_clone)]
pub struct BackupSecretsBundle {
    /// The backup decryption key, encoded as unpadded base64.
    pub key: String,
    /// The backup version which this backup decryption key is used with.
    pub backup_version: String,
}

#[wasm_bindgen]
impl SecretsBundle {
    /// The seed of the master key encoded as unpadded base64.
    #[wasm_bindgen(getter, js_name = "masterKey")]
    pub fn master_key(&self) -> String {
        self.inner.cross_signing.master_key.clone()
    }

    /// The seed of the self signing key encoded as unpadded base64.
    #[wasm_bindgen(getter, js_name = "selfSigningKey")]
    pub fn self_signing_key(&self) -> String {
        self.inner.cross_signing.self_signing_key.clone()
    }

    /// The seed of the user signing key encoded as unpadded base64.
    #[wasm_bindgen(getter, js_name = "userSigningKey")]
    pub fn user_signing_key(&self) -> String {
        self.inner.cross_signing.user_signing_key.clone()
    }

    /// The bundle of the backup decryption key and backup version if any.
    #[wasm_bindgen(getter, js_name = "backupBundle")]
    pub fn backup_bundle(&self) -> Option<BackupSecretsBundle> {
        if let Some(BackupSecrets::MegolmBackupV1Curve25519AesSha2(backup)) = &self.inner.backup {
            Some(BackupSecretsBundle {
                key: backup.key.to_base64(),
                backup_version: backup.backup_version.clone(),
            })
        } else {
            None
        }
    }

    /// Serialize the [`SecretsBundle`] to a JSON object.
    pub fn to_json(&self) -> Result<JsValue, JsError> {
        Ok(serde_wasm_bindgen::to_value(&self.inner)?)
    }

    /// Deserialize the [`SecretsBundle`] from a JSON object.
    pub fn from_json(json: JsValue) -> Result<SecretsBundle, JsError> {
        let bundle = serde_wasm_bindgen::from_value(json)?;

        Ok(Self { inner: bundle })
    }
}

impl_from_to_inner!(matrix_sdk_crypto::types::SecretsBundle => SecretsBundle);
