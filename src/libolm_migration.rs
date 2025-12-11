// Copyright 2023 The Matrix.org Foundation C.I.C.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Migration from libolm to Vodozemac.

use std::time::Duration;

use js_sys::{Date, Promise, Uint8Array};
use matrix_sdk_common::{
    js_tracing::JsLogger,
    ruma::{DeviceKeyAlgorithm, MilliSecondsSinceUnixEpoch, SecondsSinceUnixEpoch, UInt},
};
use matrix_sdk_crypto::{
    olm::PrivateCrossSigningIdentity,
    store::{
        types::{BackupDecryptionKey, Changes, PendingChanges},
        DynCryptoStore,
    },
    types::{EventEncryptionAlgorithm, SigningKeys},
    vodozemac,
    vodozemac::{Curve25519PublicKey, Ed25519PublicKey},
    Session,
};
use tracing::dispatcher;
use wasm_bindgen::prelude::*;

use crate::{
    future::future_to_promise,
    identifiers::{DeviceId, RoomId, UserId},
    store::StoreHandle,
    tracing::logger_to_dispatcher,
};

type Result<T, E = JsError> = std::result::Result<T, E>;

/// Migration routines
///
/// The public methods are exposed as static methods on this class, for
/// namespacing and to enable easier mocking in unit tests.
#[wasm_bindgen()]
#[derive(Debug, Default)]
pub struct Migration {}

/// The base dataset that is important to migrate to the Rust SDK.
///
/// Can be imported into the rust store with {@link Migration::migrateBaseData}.
#[wasm_bindgen(getter_with_clone)]
#[derive(Debug, Default, Clone)]
pub struct BaseMigrationData {
    /// The user id of the account owner.
    #[wasm_bindgen(js_name = "userId")]
    pub user_id: Option<UserId>,

    /// The device ID of the account owner.
    #[wasm_bindgen(js_name = "deviceId")]
    pub device_id: Option<DeviceId>,

    /// The pickle string holding the Olm Account, as returned by
    /// `olm_pickle_account` in libolm.
    #[wasm_bindgen(js_name = "pickledAccount")]
    pub pickled_account: String,

    /// The backup version that is currently active.
    #[wasm_bindgen(js_name = "backupVersion")]
    pub backup_version: Option<String>,

    /// The backup recovery key, as a base64-encoded string.
    #[wasm_bindgen(js_name = "backupRecoveryKey")]
    pub backup_recovery_key: Option<String>,

    /// The private, base64-encoded, master cross-signing key.
    #[wasm_bindgen(js_name = "privateCrossSigningMasterKey")]
    pub private_cross_signing_master_key: Option<String>,

    /// The private, base64-encoded, self-signing key.
    #[wasm_bindgen(js_name = "privateCrossSigningSelfSigningKey")]
    pub private_cross_signing_self_signing_key: Option<String>,

    /// The private, base64-encoded, user-signing key.
    #[wasm_bindgen(js_name = "privateCrossSigningUserSigningKey")]
    pub private_cross_signing_user_signing_key: Option<String>,
}

#[wasm_bindgen]
impl BaseMigrationData {
    /// Create a new `BaseMigrationData` with default values.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self::default()
    }
}

#[wasm_bindgen]
impl Migration {
    /// Import the base dataset from a libolm-based setup to a vodozemac-based
    /// setup stored in IndexedDB.
    ///
    /// Populates the user credentials, Olm account, backup data, etc. This is
    /// the first step in the migration process. Once this base data is
    /// imported, further data can be imported with {@link
    /// migrateOlmSessions}, {@link migrateMegolmSessions}, and TODO room
    /// settings.
    ///
    /// # Arguments
    ///
    /// * `data` - The data to be migrated
    /// * `pickle_key` - The libolm pickle key that was used to pickle the olm
    ///   account objects.
    /// * `store_handle` - A connection to the CryptoStore which will be used to
    ///   store the vodozemac data.
    /// * `logger` - An optional logger instance to use for writing log messages
    ///   during the migration operation. An instance of `JsLogger`.
    #[wasm_bindgen(js_name = "migrateBaseData", unchecked_return_type = "Promise<void>")]
    pub fn migrate_base_data(
        data: &BaseMigrationData,
        pickle_key: Uint8Array,
        store_handle: &StoreHandle,
        logger: Option<JsLogger>,
    ) -> Promise {
        let _guard = dispatcher::set_default(&logger_to_dispatcher(logger));
        let store_handle = store_handle.clone();
        let data = data.clone();
        future_to_promise(async move {
            migrate_base_data_to_store(&data, &(pickle_key.to_vec()), store_handle.store.as_ref())
                .await?;
            Ok(JsValue::UNDEFINED)
        })
    }
}

async fn migrate_base_data_to_store(
    data: &BaseMigrationData,
    pickle_key: &[u8],
    store: &DynCryptoStore,
) -> Result<(), JsError> {
    let user_id = data.user_id.clone().ok_or(JsError::new("User ID not specified"))?.inner;
    let account = vodozemac::olm::Account::from_libolm_pickle(&data.pickled_account, pickle_key)?;
    let account =
        matrix_sdk_crypto::olm::Account::from_pickle(matrix_sdk_crypto::olm::PickledAccount {
            user_id: user_id.clone(),
            device_id: data.device_id.clone().ok_or(JsError::new("Device ID not specified"))?.inner,
            pickle: account.pickle(),
            // Legacy crypto in the js-sdk does not keep a record of whether it has published the
            // device keys to the server (it does it every time the stack is started). For safety,
            // let's assume it hasn't happened yet.
            shared: false,
            dehydrated: false,
            // Assume we have 50 keys on the server, until we get a sync that says fewer.
            uploaded_signed_key_count: 50,

            // The legacy crypto stack didn't keep a record of when the device was created, so we
            // have to make something up.
            //
            // The main thing the creation time is used for is determining whether an event was sent
            // before the device was created (and hence should not expect to receive the keys).
            // To avoid incorrectly marking UTD events sent before migration as "expected UTDs", we
            // set the "creation time" to zero.
            creation_local_time: MilliSecondsSinceUnixEpoch(UInt::MIN),

            fallback_key_creation_timestamp: None,
        })?;

    let backup_decryption_key = data
        .backup_recovery_key
        .as_ref()
        .map(|k| BackupDecryptionKey::from_base64(k.as_str()))
        .transpose()?;

    let cross_signing = PrivateCrossSigningIdentity::empty(&user_id);
    cross_signing
        .import_secrets_unchecked(
            data.private_cross_signing_master_key.as_deref(),
            data.private_cross_signing_self_signing_key.as_deref(),
            data.private_cross_signing_user_signing_key.as_deref(),
        )
        .await?;

    store.save_pending_changes(PendingChanges { account: Some(account) }).await?;
    store
        .save_changes(Changes {
            private_identity: Some(cross_signing),
            backup_decryption_key,
            backup_version: data.backup_version.clone(),
            ..Default::default()
        })
        .await?;
    Ok(())
}

/// A pickled version of a `Session`.
///
/// Holds all the information that needs to be stored in a database to restore
/// an Olm Session. Can be imported into the rust store with {@link
/// Migration::migrateOlmSessions}.
#[wasm_bindgen(getter_with_clone)]
#[derive(Debug)]
pub struct PickledSession {
    /// The pickle string holding the Olm Session, as returned by
    /// `olm_pickle_session` in libolm.
    pub pickle: String,
    /// The base64-encoded public curve25519 key of the other user that we share
    /// this session with.
    #[wasm_bindgen(js_name = "senderKey")]
    pub sender_key: String,
    /// Was the session created using a fallback key?
    #[wasm_bindgen(js_name = "createdUsingFallbackKey")]
    pub created_using_fallback_key: bool,
    /// When the session was created.
    #[wasm_bindgen(js_name = "creationTime")]
    pub creation_time: Date,
    /// When the session was last used.
    #[wasm_bindgen(js_name = "lastUseTime")]
    pub last_use_time: Date,
}

#[wasm_bindgen]
impl PickledSession {
    /// Construct a new `PickledSession`, with default values.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self::default()
    }
}

#[wasm_bindgen]
impl Migration {
    /// Migrate Olm sessions of a libolm-based setup to a vodozemac-based setup
    /// stored in an indexedDB crypto store.
    ///
    /// Before this method can be used, {@link migrateBaseData} must be used to
    /// import the base data into the crypto store.
    ///
    /// This method should be called a number of times, with separate batches of
    /// `sessions`. If a progress display is given, it can be updated after
    /// each batch is successfully imported.
    ///
    /// # Arguments
    ///
    /// * `sessions` - An `Array` of {@link PickledSession}s to import. Items
    ///   inside `sessions` will be invalidated by this method.
    /// * `pickle_key` - The libolm pickle key that was used to pickle the olm
    ///   session objects.
    /// * `store_handle` - A connection to the CryptoStore which will be used to
    ///   store the vodozemac data.
    /// * `logger` - An optional logger instance to use for writing log messages
    ///   during the migration operation. An instance of `JsLogger`.
    #[wasm_bindgen(js_name = "migrateOlmSessions", unchecked_return_type = "Promise<void>")]
    pub fn migrate_olm_sessions(
        sessions: Vec<PickledSession>,
        pickle_key: Uint8Array,
        store_handle: &StoreHandle,
        logger: Option<JsLogger>,
    ) -> Result<Promise, JsError> {
        let _guard = dispatcher::set_default(&logger_to_dispatcher(logger));

        let pickle_key = pickle_key.to_vec();

        let rust_sessions = sessions
            .into_iter()
            .map(|session| libolm_pickled_session_to_rust_pickled_session(session, &pickle_key))
            .collect::<Result<_>>()?;

        let store_handle = store_handle.clone();

        Ok(future_to_promise(async move {
            import_olm_sessions_to_store(rust_sessions, store_handle.store.as_ref()).await?;
            Ok(JsValue::UNDEFINED)
        }))
    }
}

impl Default for PickledSession {
    fn default() -> Self {
        Self {
            pickle: String::new(),
            sender_key: String::new(),
            created_using_fallback_key: false,
            creation_time: Date::new(&JsValue::from(0)),
            last_use_time: Date::new(&JsValue::from(0)),
        }
    }
}

fn libolm_pickled_session_to_rust_pickled_session(
    libolm_session: PickledSession,
    pickle_key: &[u8],
) -> Result<matrix_sdk_crypto::olm::PickledSession> {
    let session = vodozemac::olm::Session::from_libolm_pickle(&libolm_session.pickle, pickle_key)?;

    let creation_time = date_to_seconds_since_epoch(&libolm_session.creation_time)
        .ok_or_else(|| JsError::new("session creation time out of range"))?;
    let last_use_time = date_to_seconds_since_epoch(&libolm_session.last_use_time)
        .ok_or_else(|| JsError::new("session last-use time out of range"))?;

    Ok(matrix_sdk_crypto::olm::PickledSession {
        pickle: session.pickle(),
        sender_key: Curve25519PublicKey::from_base64(&libolm_session.sender_key)?,
        created_using_fallback_key: libolm_session.created_using_fallback_key,
        creation_time,
        last_use_time,
    })
}

async fn import_olm_sessions_to_store(
    pickled_sessions: Vec<matrix_sdk_crypto::olm::PickledSession>,
    store: &DynCryptoStore,
) -> Result<(), JsError> {
    let account = store
        .load_account()
        .await?
        .ok_or(JsError::new("Base data must be imported before calling `migrateOlmSessions`"))?;

    let sessions = pickled_sessions
        .into_iter()
        .map(|pickled_session| {
            // Session::from_pickle normally needs the device keys from storage
            // (which will include cross-signing signatures), for embedding the
            // key in outgoing messages.  But in this case, it is just getting
            // stored, so we can use the device keys generated by the account.
            Session::from_pickle(account.device_keys(), pickled_session)
                .expect("The account is invalid")
        })
        .collect();

    store.save_changes(Changes { sessions, ..Default::default() }).await?;
    Ok(())
}

/// A pickled version of an `InboundGroupSession`.
///
/// Holds all the information that needs to be stored in a database to restore
/// an InboundGroupSession.
#[wasm_bindgen(getter_with_clone)]
#[derive(Debug, Default)]
pub struct PickledInboundGroupSession {
    /// The pickle string holding the Megolm Session, as returned by
    /// `olm_pickle_inbound_group_session` in libolm.
    pub pickle: String,

    /// The public curve25519 key of the account that sent us the session.
    #[wasm_bindgen(js_name = "senderKey")]
    pub sender_key: String,

    /// The public ed25519 key of the account that is believed to have initiated
    /// the session, if known.
    ///
    /// If the session was received directly from the creator via an
    /// Olm-encrypted `m.room_key` event, this value is taken from the `keys`
    /// property of the plaintext payload of that event (see
    /// [`m.olm.v1.curve25519-aes-sha2`]).
    ///
    /// If the session was forwarded to us using an [`m.forwarded_room_key`],
    /// this value is a copy of the `sender_claimed_ed25519_key` from the
    /// content of the event.
    ///
    /// [`m.olm.v1.curve25519-aes-sha2`]: https://spec.matrix.org/v1.9/client-server-api/#molmv1curve25519-aes-sha2
    /// [`m.forwarded_room_key`]: https://spec.matrix.org/v1.9/client-server-api/#mforwarded_room_key
    #[wasm_bindgen(js_name = "senderSigningKey")]
    pub sender_signing_key: Option<String>,

    /// The id of the room that the session is used in.
    ///
    /// Nullable so that a `PickledInboundGroupSession` can be constructed
    /// incrementally. Must be populated!
    #[wasm_bindgen(js_name = "roomId")]
    pub room_id: Option<RoomId>,

    /// Flag remembering if the session was directly sent to us by the sender
    /// or if it was imported.
    pub imported: bool,

    /// Flag remembering if the session has been backed up.
    #[wasm_bindgen(js_name = "backedUp")]
    pub backed_up: bool,
}

#[wasm_bindgen]
impl PickledInboundGroupSession {
    /// Construct a new `PickledInboundGroupSession`, with default values.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self::default()
    }
}

#[wasm_bindgen]
impl Migration {
    /// Migrate Megolm sessions of a libolm-based setup to a vodozemac-based
    /// setup stored in an indexedDB crypto store.
    ///
    /// Before this method can be used, {@link migrateBaseData} must be used to
    /// import the base data into the crypto store.
    ///
    /// This method should be called a number of times, with separate batches of
    /// `sessions`. If a progress display is given, it can be updated after
    /// each batch is successfully imported.
    ///
    /// # Arguments
    ///
    /// * `sessions` - An `Array` of {@link PickledInboundGroupSession}s to
    ///   import. Items inside `sessions` will be invalidated by this method.
    /// * `pickle_key` - The libolm pickle key that was used to pickle the
    ///   megolm session objects.
    /// * `store_handle` - A connection to the CryptoStore which will be used to
    ///   store the vodozemac data.
    /// * `logger` - An optional logger instance to use for writing log messages
    ///   during the migration operation. An instance of `JsLogger`.
    #[wasm_bindgen(js_name = "migrateMegolmSessions", unchecked_return_type = "Promise<void>")]
    pub fn migrate_megolm_sessions(
        sessions: Vec<PickledInboundGroupSession>,
        pickle_key: Uint8Array,
        store_handle: &StoreHandle,
        logger: Option<JsLogger>,
    ) -> Result<Promise, JsError> {
        let _guard = dispatcher::set_default(&logger_to_dispatcher(logger));
        let pickle_key = pickle_key.to_vec();

        let rust_sessions = sessions
            .into_iter()
            .map(|session| {
                libolm_pickled_megolm_session_to_rust_pickled_session(session, &pickle_key)
            })
            .collect::<Result<_>>()?;

        let store_handle = store_handle.clone();
        Ok(future_to_promise(async move {
            import_megolm_sessions_to_store(rust_sessions, store_handle.store.as_ref()).await?;
            Ok(JsValue::UNDEFINED)
        }))
    }
}

fn libolm_pickled_megolm_session_to_rust_pickled_session(
    libolm_session: PickledInboundGroupSession,
    pickle_key: &[u8],
) -> Result<matrix_sdk_crypto::olm::PickledInboundGroupSession> {
    let pickle = vodozemac::megolm::InboundGroupSession::from_libolm_pickle(
        &libolm_session.pickle,
        pickle_key,
    )?
    .pickle();

    let sender_key = Curve25519PublicKey::from_base64(&libolm_session.sender_key)?;

    let mut sender_signing_keys = SigningKeys::new();
    if let Some(key) = libolm_session.sender_signing_key {
        sender_signing_keys
            .insert(DeviceKeyAlgorithm::Ed25519, Ed25519PublicKey::from_base64(&key)?.into());
    }

    Ok(matrix_sdk_crypto::olm::PickledInboundGroupSession {
        pickle,
        sender_key,
        signing_key: sender_signing_keys,
        sender_data: Default::default(),
        forwarder_data: None,
        room_id: libolm_session
            .room_id
            .clone()
            .ok_or_else(|| JsError::new("Room ID not specified for megolm session"))?
            .inner,
        imported: libolm_session.imported,
        backed_up: libolm_session.backed_up,
        history_visibility: None,
        algorithm: EventEncryptionAlgorithm::MegolmV1AesSha2,
        shared_history: false,
    })
}

async fn import_megolm_sessions_to_store(
    pickled_sessions: Vec<matrix_sdk_crypto::olm::PickledInboundGroupSession>,
    store: &DynCryptoStore,
) -> Result<(), JsError> {
    let inbound_group_sessions = pickled_sessions
        .into_iter()
        .map(matrix_sdk_crypto::olm::InboundGroupSession::from_pickle)
        .collect::<Result<_, _>>()?;

    store.save_changes(Changes { inbound_group_sessions, ..Default::default() }).await?;
    Ok(())
}

/// Convert a Javascript `Date` into `SecondsSinceUnixEpoch`.
///
/// Returns `None` if the Date cannot be represented as a
/// `SecondsSinceUnixEpoch`
fn date_to_seconds_since_epoch(date: &Date) -> Option<SecondsSinceUnixEpoch> {
    // javascript Dates are defined to be in milliseconds since the epoch
    let duration_since_epoch = Duration::from_millis(date.get_time() as u64);
    Some(SecondsSinceUnixEpoch(UInt::new(duration_since_epoch.as_secs())?))
}
