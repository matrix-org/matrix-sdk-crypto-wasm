//! Extra types, like `Signatures`.

use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};

use js_sys::{Array, JsString, Map, Set};
use matrix_sdk_common::ruma::OwnedRoomId;
use matrix_sdk_crypto::{
    backups::{
        SignatureState as InnerSignatureState, SignatureVerification as InnerSignatureVerification,
    },
    MediaEncryptionInfo,
};
use tracing::warn;
use wasm_bindgen::prelude::*;

use crate::{
    encryption::EncryptionAlgorithm,
    identifiers::{DeviceKeyId, RoomId, UserId},
    impl_from_to_inner,
    responses::ToDeviceEncryptionInfo,
    vodozemac::Ed25519Signature,
};

/// A collection of `Signature`.
#[wasm_bindgen]
#[derive(Debug, Default)]
pub struct Signatures {
    inner: matrix_sdk_crypto::types::Signatures,
}

impl_from_to_inner!(matrix_sdk_crypto::types::Signatures => Signatures);

#[wasm_bindgen]
impl Signatures {
    /// Creates a new, empty, signatures collection.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        matrix_sdk_crypto::types::Signatures::new().into()
    }

    /// Add the given signature from the given signer and the given key ID to
    /// the collection.
    #[wasm_bindgen(js_name = "addSignature")]
    pub fn add_signature(
        &mut self,
        signer: &UserId,
        key_id: &DeviceKeyId,
        signature: &Ed25519Signature,
    ) -> Option<MaybeSignature> {
        self.inner
            .add_signature(signer.inner.clone(), key_id.inner.clone(), signature.inner)
            .map(Into::into)
    }

    /// Try to find an Ed25519 signature from the given signer with
    /// the given key ID.
    #[wasm_bindgen(js_name = "getSignature")]
    pub fn get_signature(&self, signer: &UserId, key_id: &DeviceKeyId) -> Option<Ed25519Signature> {
        self.inner.get_signature(signer.inner.as_ref(), key_id.inner.as_ref()).map(Into::into)
    }

    /// Get the map of signatures that belong to the given user.
    pub fn get(&self, signer: &UserId) -> Option<Map> {
        let map = Map::new();

        for (device_key_id, maybe_signature) in
            self.inner.get(signer.inner.as_ref()).map(|map| {
                map.iter().map(|(device_key_id, maybe_signature)| {
                    (
                        device_key_id.as_str().to_owned(),
                        MaybeSignature::from(maybe_signature.clone()),
                    )
                })
            })?
        {
            map.set(&device_key_id.into(), &maybe_signature.into());
        }

        Some(map)
    }

    /// Remove all the signatures we currently hold.
    pub fn clear(&mut self) {
        self.inner.clear();
    }

    /// Do we hold any signatures or is our collection completely
    /// empty.
    #[wasm_bindgen(js_name = "isEmpty")]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// How many signatures do we currently hold.
    #[wasm_bindgen(getter)]
    pub fn count(&self) -> usize {
        self.inner.signature_count()
    }

    /// Get the json with all signatures
    #[wasm_bindgen(js_name = "asJSON")]
    pub fn as_json(&self) -> Result<JsString, JsError> {
        Ok(serde_json::to_string(&self.inner)?.into())
    }
}

/// Represents a potentially decoded signature (but not a validated
/// one).
#[wasm_bindgen]
#[derive(Debug)]
pub struct Signature {
    inner: matrix_sdk_crypto::types::Signature,
}

impl_from_to_inner!(matrix_sdk_crypto::types::Signature => Signature);

#[wasm_bindgen]
impl Signature {
    /// Get the Ed25519 signature, if this is one.
    #[wasm_bindgen(getter)]
    pub fn ed25519(&self) -> Option<Ed25519Signature> {
        self.inner.ed25519().map(Into::into)
    }

    /// Convert the signature to a base64 encoded string.
    #[wasm_bindgen(js_name = "toBase64")]
    pub fn to_base64(&self) -> String {
        self.inner.to_base64()
    }
}

type MaybeSignatureInner =
    Result<matrix_sdk_crypto::types::Signature, matrix_sdk_crypto::types::InvalidSignature>;

/// Represents a signature that is either valid _or_ that could not be
/// decoded.
#[wasm_bindgen]
#[derive(Debug)]
pub struct MaybeSignature {
    inner: MaybeSignatureInner,
}

impl_from_to_inner!(MaybeSignatureInner => MaybeSignature);

#[wasm_bindgen]
impl MaybeSignature {
    /// Check whether the signature has been successfully decoded.
    #[wasm_bindgen(js_name = "isValid")]
    pub fn is_valid(&self) -> bool {
        self.inner.is_ok()
    }

    /// Check whether the signature could not be successfully decoded.
    #[wasm_bindgen(js_name = "isInvalid")]
    pub fn is_invalid(&self) -> bool {
        self.inner.is_err()
    }

    /// The signature, if successfully decoded.
    #[wasm_bindgen(getter)]
    pub fn signature(&self) -> Option<Signature> {
        self.inner.as_ref().cloned().map(Into::into).ok()
    }

    /// The base64 encoded string that is claimed to contain a
    /// signature but could not be decoded, if any.
    #[wasm_bindgen(getter, js_name = "invalidSignatureSource")]
    pub fn invalid_signature_source(&self) -> Option<String> {
        match &self.inner {
            Ok(_) => None,
            Err(signature) => Some(signature.source.clone()),
        }
    }
}

/// The result of a signature verification of a signed JSON object.
#[derive(Debug)]
#[wasm_bindgen]
pub struct SignatureVerification {
    pub(crate) inner: InnerSignatureVerification,
}

/// The result of a signature check.
#[derive(Debug)]
#[wasm_bindgen]
pub enum SignatureState {
    /// The signature is missing.
    Missing = 0,
    /// The signature is invalid.
    Invalid = 1,
    /// The signature is valid but the device or user identity that created the
    /// signature is not trusted.
    ValidButNotTrusted = 2,
    /// The signature is valid and the device or user identity that created the
    /// signature is trusted.
    ValidAndTrusted = 3,
}

impl From<InnerSignatureState> for SignatureState {
    fn from(val: InnerSignatureState) -> Self {
        match val {
            InnerSignatureState::Missing => SignatureState::Missing,
            InnerSignatureState::Invalid => SignatureState::Invalid,
            InnerSignatureState::ValidButNotTrusted => SignatureState::ValidButNotTrusted,
            InnerSignatureState::ValidAndTrusted => SignatureState::ValidAndTrusted,
        }
    }
}

#[wasm_bindgen]
impl SignatureVerification {
    /// Give the backup signature state from the current device.
    /// See SignatureState for values
    #[wasm_bindgen(getter, js_name = "deviceState")]
    pub fn device_state(&self) -> SignatureState {
        self.inner.device_signature.into()
    }

    /// Give the backup signature state from the current user identity.
    /// See SignatureState for values
    #[wasm_bindgen(getter, js_name = "userState")]
    pub fn user_state(&self) -> SignatureState {
        self.inner.user_identity_signature.into()
    }

    /// Is the result considered to be trusted?
    ///
    /// This tells us if the result has a valid signature from any of the
    /// following:
    ///
    /// * Our own device
    /// * Our own user identity, provided the identity is trusted as well
    /// * Any of our own devices, provided the device is trusted as well
    #[wasm_bindgen()]
    pub fn trusted(&self) -> bool {
        self.inner.trusted()
    }
}

/// The result of a call to {@link OlmMachine.importExportedRoomKeys} or
/// {@link OlmMachine.importBackedUpRoomKeys}.
#[derive(Clone, Debug)]
#[wasm_bindgen]
pub struct RoomKeyImportResult {
    /// The number of room keys that were imported.
    #[wasm_bindgen(readonly, js_name = "importedCount")]
    pub imported_count: usize,

    /// The total number of room keys that were found in the export.
    #[wasm_bindgen(readonly, js_name = "totalCount")]
    pub total_count: usize,

    /// The map of keys that were imported.
    ///
    /// A map from room id to a map of the sender key to a set of session ids.
    keys: BTreeMap<OwnedRoomId, BTreeMap<String, BTreeSet<String>>>,
}

#[wasm_bindgen]
impl RoomKeyImportResult {
    /// The keys that were imported.
    ///
    /// A Map from room id to a Map of the sender key to a Set of session ids.
    ///
    /// Typescript type: `Map<string, Map<string, Set<string>>`.
    pub fn keys(&self) -> Map {
        let key_map = Map::new();

        for (room_id, room_result) in self.keys.iter() {
            let room_map = Map::new();
            key_map.set(&JsString::from(room_id.to_string()), &room_map);

            for (sender_key, sessions) in room_result.iter() {
                let s: Array = sessions.iter().map(|s| JsString::from(s.as_ref())).collect();
                room_map.set(&JsString::from(sender_key.as_ref()), &Set::new(&s));
            }
        }

        key_map
    }
}

impl From<matrix_sdk_crypto::RoomKeyImportResult> for RoomKeyImportResult {
    fn from(value: matrix_sdk_crypto::RoomKeyImportResult) -> Self {
        RoomKeyImportResult {
            imported_count: value.imported_count,
            total_count: value.total_count,
            keys: value.keys,
        }
    }
}

/// Room encryption settings which are modified by state events or user options
#[derive(Clone, Debug)]
#[wasm_bindgen(getter_with_clone)]
pub struct RoomSettings {
    /// The encryption algorithm that should be used in the room.
    ///
    /// Should be one of the members of {@link EncryptionAlgorithm}.
    pub algorithm: EncryptionAlgorithm,

    /// Whether state event encryption is enabled.
    #[cfg(feature = "experimental-encrypted-state-events")]
    #[wasm_bindgen(js_name = "encryptStateEvents")]
    pub encrypt_state_events: bool,

    /// Whether untrusted devices should receive room keys. If this is `false`,
    /// they will be excluded from the conversation.
    #[wasm_bindgen(js_name = "onlyAllowTrustedDevices")]
    pub only_allow_trusted_devices: bool,

    /// The maximum time, in milliseconds, that an encryption session should be
    /// used for, before it is rotated.
    #[wasm_bindgen(js_name = "sessionRotationPeriodMs")]
    pub session_rotation_period_ms: Option<f64>,

    /// The maximum number of messages an encryption session should be used for,
    /// before it is rotated.
    #[wasm_bindgen(js_name = "sessionRotationPeriodMessages")]
    pub session_rotation_period_messages: Option<f64>,
}

#[wasm_bindgen]
impl RoomSettings {
    /// Create a new `RoomSettings` with default values.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self::default()
    }
}

impl Default for RoomSettings {
    fn default() -> Self {
        Self {
            algorithm: EncryptionAlgorithm::MegolmV1AesSha2,
            #[cfg(feature = "experimental-encrypted-state-events")]
            encrypt_state_events: false,
            only_allow_trusted_devices: false,
            session_rotation_period_ms: None,
            session_rotation_period_messages: None,
        }
    }
}

impl From<matrix_sdk_crypto::store::types::RoomSettings> for RoomSettings {
    fn from(value: matrix_sdk_crypto::store::types::RoomSettings) -> Self {
        Self {
            algorithm: value.algorithm.into(),
            #[cfg(feature = "experimental-encrypted-state-events")]
            encrypt_state_events: value.encrypt_state_events,
            only_allow_trusted_devices: value.only_allow_trusted_devices,
            session_rotation_period_ms: value
                .session_rotation_period
                .map(|duration| duration.as_millis() as f64),
            session_rotation_period_messages: value
                .session_rotation_period_messages
                .map(|count| count as f64),
        }
    }
}

impl From<&RoomSettings> for matrix_sdk_crypto::store::types::RoomSettings {
    fn from(value: &RoomSettings) -> Self {
        Self {
            algorithm: value.algorithm.clone().into(),
            #[cfg(feature = "experimental-encrypted-state-events")]
            encrypt_state_events: value.encrypt_state_events,
            only_allow_trusted_devices: value.only_allow_trusted_devices,
            session_rotation_period: value
                .session_rotation_period_ms
                .map(|millis| Duration::from_millis(millis as u64)),
            session_rotation_period_messages: value
                .session_rotation_period_messages
                .map(|count| count as usize),
        }
    }
}

/// The type of a {@link ProcessedToDeviceEvent}.
#[wasm_bindgen]
#[derive(Debug, Clone)]
pub enum ProcessedToDeviceEventType {
    /// A successfully-decrypted encrypted to-device message.
    Decrypted,

    /// An encrypted to-device message which could not be decrypted.
    UnableToDecrypt,

    /// An unencrypted to-device message (sent in clear).
    PlainText,

    /// An invalid to-device message that was ignored because it is missing some
    /// required information to be processed (like no event `type` for
    /// example)
    Invalid,
}

/// Represents an encrypted to-device event, after it has been decrypted.
#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct DecryptedToDeviceEvent {
    /// The decrypted event, as if it had been sent in the clear, encoded as
    /// JSON.
    ///
    /// Typically contains properties `type`, `sender` and `content`.
    ///
    /// (For room keys or secrets, some part of the content might have been
    /// zeroized).
    #[wasm_bindgen(readonly, getter_with_clone, js_name = "rawEvent")]
    pub raw_event: JsString,

    /// The encryption information for the event.
    #[wasm_bindgen(readonly, getter_with_clone, js_name = "encryptionInfo")]
    pub encryption_info: ToDeviceEncryptionInfo,
}

#[wasm_bindgen]
impl DecryptedToDeviceEvent {
    /// The type of processed to-device event. Always {@link
    /// ProcessedToDeviceEventType.Decrypted} for this type.
    #[wasm_bindgen(getter, js_name = "type")]
    pub fn processed_type(&self) -> ProcessedToDeviceEventType {
        ProcessedToDeviceEventType::Decrypted
    }
}

/// Represents a to-device event sent in the clear.
#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct PlainTextToDeviceEvent {
    /// The to-device message, containing `type`, `sender` and `content` fields,
    /// encoded as JSON.
    #[wasm_bindgen(readonly, getter_with_clone, js_name = "rawEvent")]
    pub raw_event: JsString,
}

#[wasm_bindgen]
impl PlainTextToDeviceEvent {
    /// The type of processed to-device event. Always {@link
    /// ProcessedToDeviceEventType.PlainText} for this type.
    #[wasm_bindgen(getter, js_name = "type")]
    pub fn processed_type(&self) -> ProcessedToDeviceEventType {
        ProcessedToDeviceEventType::PlainText
    }
}

/// Reason code for a to-device decryption failure
#[wasm_bindgen]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ToDeviceUnableToDecryptReason {
    /// An error occurred while encrypting the event. This covers all
    /// `OlmError` types.
    DecryptionFailure,

    /// We refused to decrypt the message because the sender's device is not
    /// verified, or more generally, the sender's identity did not match the
    /// trust requirement we were asked to provide.
    UnverifiedSenderDevice,

    /// We have no `OlmMachine`. This should not happen unless we forget to set
    /// things up by calling `OlmMachine::activate()`.
    NoOlmMachine,

    /// The Matrix SDK was compiled without encryption support.
    EncryptionIsDisabled,
}

impl From<matrix_sdk_common::deserialized_responses::ToDeviceUnableToDecryptReason>
    for ToDeviceUnableToDecryptReason
{
    fn from(
        value: matrix_sdk_common::deserialized_responses::ToDeviceUnableToDecryptReason,
    ) -> Self {
        use matrix_sdk_common::deserialized_responses::ToDeviceUnableToDecryptReason::*;
        match value {
            DecryptionFailure => Self::DecryptionFailure,
            UnverifiedSenderDevice => Self::UnverifiedSenderDevice,
            NoOlmMachine => Self::NoOlmMachine,
            EncryptionIsDisabled => Self::EncryptionIsDisabled,
        }
    }
}

/// Metadata about a to-device event that could not be decrypted.
#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct ToDeviceUnableToDecryptInfo {
    /// Reason code for the decryption failure
    pub reason: ToDeviceUnableToDecryptReason,
}

impl From<matrix_sdk_common::deserialized_responses::ToDeviceUnableToDecryptInfo>
    for ToDeviceUnableToDecryptInfo
{
    fn from(value: matrix_sdk_common::deserialized_responses::ToDeviceUnableToDecryptInfo) -> Self {
        Self { reason: value.reason.into() }
    }
}

/// Represents an encrypted to-device event that could not be decrypted.
#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct UTDToDeviceEvent {
    /// The original message (of type `m.room.encrypted`) that failed to be
    /// decrypted, encoded as JSON.
    #[wasm_bindgen(readonly, getter_with_clone, js_name = "rawEvent")]
    pub raw_event: JsString,
    /// Information on the reason we failed to decrypt
    #[wasm_bindgen(readonly, getter_with_clone, js_name = "utdInfo")]
    pub utd_info: ToDeviceUnableToDecryptInfo,
}

#[wasm_bindgen]
impl UTDToDeviceEvent {
    /// The type of processed to-device event. Always {@link
    /// ProcessedToDeviceEventType.UnableToDecrypt} for this type.
    #[wasm_bindgen(getter, js_name = "type")]
    pub fn processed_type(&self) -> ProcessedToDeviceEventType {
        ProcessedToDeviceEventType::UnableToDecrypt
    }
}

/// Represents an invalid to-device event that was ignored (because it is
/// missing some mandatory fields, for example).
#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct InvalidToDeviceEvent {
    /// The original message as received from sync, encoded as JSON.
    #[wasm_bindgen(readonly, getter_with_clone, js_name = "rawEvent")]
    pub raw_event: JsString,
    // TODO: Add some error information here?
}

#[wasm_bindgen]
impl InvalidToDeviceEvent {
    /// The type of processed to-device event. Always {@link
    /// ProcessedToDeviceEventType.Invalid} for this type.
    #[wasm_bindgen(getter, js_name = "type")]
    pub fn processed_type(&self) -> ProcessedToDeviceEventType {
        ProcessedToDeviceEventType::Invalid
    }
}

/// Convert an `ProcessedToDeviceEvent` into a `JsValue`, ready to return to
/// JavaScript.
///
/// JavaScript has no complex enums like Rust. To return structs of different
/// types, we have no choice other than hiding everything behind a `JsValue`.
///
/// We attempt to map the event onto one of the following types:
///  * [`DecryptedToDeviceEvent`]
///  * [`UTDToDeviceEvent`]
///  * [`PlainTextToDeviceEvent`]
///  * [`InvalidToDeviceEvent`].
///
/// We then convert that result into a [`JsValue`].
///
/// If the event cannot be mapped into one of those types, we instead return
/// `None`, indicating the event should be discarded.
pub fn processed_to_device_event_to_js_value(
    processed_to_device_event: matrix_sdk_common::deserialized_responses::ProcessedToDeviceEvent,
) -> Option<JsValue> {
    let result = match processed_to_device_event {
        matrix_sdk_common::deserialized_responses::ProcessedToDeviceEvent::Decrypted {
            raw,
            encryption_info,
        } => {
            match encryption_info.try_into() {
                Ok(encryption_info) => {
                    DecryptedToDeviceEvent { raw_event: raw.json().get().into(), encryption_info }
                        .into()
                }
                Err(e) => {
                    // This can only happen if we receive an encrypted to-device event which is
                    // encrypted with an algorithm we don't recognise. This
                    // shouldn't really happen, unless the wasm bindings have
                    // gotten way out of step with the underlying SDK.
                    //
                    // There's not a lot we can do here: we just throw away the event.
                    warn!("Dropping incoming to-device event with invalid encryption_info: {e:?}");
                    return None;
                }
            }
        }
        matrix_sdk_common::deserialized_responses::ProcessedToDeviceEvent::UnableToDecrypt {
            encrypted_event,
            utd_info,
        } => UTDToDeviceEvent {
            raw_event: encrypted_event.json().get().into(),
            utd_info: utd_info.into(),
        }
        .into(),
        matrix_sdk_common::deserialized_responses::ProcessedToDeviceEvent::PlainText(plain) => {
            PlainTextToDeviceEvent { raw_event: plain.json().get().into() }.into()
        }
        matrix_sdk_common::deserialized_responses::ProcessedToDeviceEvent::Invalid(invalid) => {
            InvalidToDeviceEvent { raw_event: invalid.json().get().into() }.into()
        }
    };
    Some(result)
}

/// Information on a stored room key bundle data event.
#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct StoredRoomKeyBundleData {
    pub(crate) inner: matrix_sdk_crypto::store::types::StoredRoomKeyBundleData,
}

#[wasm_bindgen]
impl StoredRoomKeyBundleData {
    /// The user that sent us this data.
    #[wasm_bindgen(getter, js_name = "senderUser")]
    pub fn sender_user(&self) -> UserId {
        self.inner.sender_user.clone().into()
    }

    /// The room that these keys are for.
    #[wasm_bindgen(getter, js_name = "roomId")]
    pub fn room_id(&self) -> RoomId {
        self.inner.bundle_data.room_id.clone().into()
    }

    /// The location of the bundle.
    #[wasm_bindgen(getter)]
    pub fn url(&self) -> String {
        self.inner.bundle_data.file.url.to_string()
    }

    /// The JSON-encoded encryption info for the key bundle.
    ///
    /// @deprecated Should not be used within applications.
    #[wasm_bindgen(getter, js_name = "encryptionInfo")]
    pub fn encryption_info(&self) -> String {
        serde_json::to_string(&MediaEncryptionInfo::from(self.inner.bundle_data.file.clone()))
            .expect("Unable to serialize MediaEncryptionInfo")
    }
}

impl From<matrix_sdk_crypto::store::types::StoredRoomKeyBundleData> for StoredRoomKeyBundleData {
    fn from(value: matrix_sdk_crypto::store::types::StoredRoomKeyBundleData) -> Self {
        Self { inner: value }
    }
}
