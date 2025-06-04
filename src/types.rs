//! Extra types, like `Signatures`.

use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};

use js_sys::{Array, JsString, Map, Set};
use matrix_sdk_common::ruma::OwnedRoomId;
use matrix_sdk_crypto::backups::{
    SignatureState as InnerSignatureState, SignatureVerification as InnerSignatureVerification,
};
use wasm_bindgen::prelude::*;

use crate::{
    encryption::EncryptionAlgorithm,
    identifiers::{DeviceKeyId, UserId},
    impl_from_to_inner,
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
            only_allow_trusted_devices: false,
            session_rotation_period_ms: None,
            session_rotation_period_messages: None,
        }
    }
}

impl From<matrix_sdk_crypto::store::RoomSettings> for RoomSettings {
    fn from(value: matrix_sdk_crypto::store::RoomSettings) -> Self {
        Self {
            algorithm: value.algorithm.into(),
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

impl From<&RoomSettings> for matrix_sdk_crypto::store::RoomSettings {
    fn from(value: &RoomSettings) -> Self {
        Self {
            algorithm: value.algorithm.clone().into(),
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

/// Represent the type of {@link ProcessedToDeviceEvent}.
#[wasm_bindgen]
#[derive(Debug, Clone)]
pub enum ProcessedToDeviceEventType {
    /// A successfully-decrypted encrypted event.
    Decrypted,

    /// An encrypted event which could not be decrypted.
    UnableToDecrypt,

    /// An unencrypted event (sent in clear).
    PlainText,

    /// An invalid to device event that was ignored because it is missing some
    /// required information to be processed (like no event `type` for
    /// example)
    Invalid,
}

/// Represent a ToDevice event after it has been decrypted by {@link
/// OlmMachine#receiveSyncChanges}.
#[wasm_bindgen(getter_with_clone)]
#[derive(Debug, Clone)]
pub struct DecryptedToDeviceEvent {
    /// The type of processed event
    #[wasm_bindgen(getter_with_clone, js_name = "type")]
    pub processed_type: ProcessedToDeviceEventType,

    /// A JSON-encoded string containing the processed event.
    /// The decrypted event as if it was sent in clear (For room keys or secrets
    /// some part of the content might have been zeroize'd).
    #[wasm_bindgen(readonly, js_name = "wireEvent")]
    pub wire_event: JsString,


    #[wasm_bindgen(readonly, js_name = "encryptionInfo")]
    /// The encryption information (olm variant) for the event.
    pub encryption_info: crate::responses::EncryptionInfo,
}

/// Represent a ToDevice event sent in clear after it has been processed {@link
/// OlmMachine#receiveSyncChanges}.
#[wasm_bindgen(getter_with_clone)]
#[derive(Debug, Clone)]
pub struct PlainTextToDeviceEvent {
    /// The type of processed event
    #[wasm_bindgen(getter_with_clone, js_name = "type")]
    pub processed_type: ProcessedToDeviceEventType,

    /// A JSON-encoded string containing the messsage.
    #[wasm_bindgen(readonly, js_name = "wireEvent")]
    pub wire_event: JsString,
}

/// Represent a ToDevice event that could not be decrypted after it has been
/// processed.
#[wasm_bindgen(getter_with_clone)]
#[derive(Debug, Clone)]
pub struct UTDToDeviceEvent {
    /// The type of processed event
    #[wasm_bindgen(getter_with_clone, js_name = "type")]
    pub processed_type: ProcessedToDeviceEventType,

    /// A JSON-encoded string containing the original message of type
    /// `m.room.encrypted`
    #[wasm_bindgen(readonly, js_name = "wireEvent")]
    pub wire_event: JsString,
    // TODO: Add some OlmError in the future
}

/// Represent an invalid ToDevice event that was ignored because it is missing
/// some mandatory fields for example.
#[wasm_bindgen(getter_with_clone)]
#[derive(Debug, Clone)]
pub struct InvalidToDeviceEvent {
    /// The type of processed event
    #[wasm_bindgen(getter_with_clone, js_name = "type")]
    pub processed_type: ProcessedToDeviceEventType,

    /// A JSON-encoded string containing the original message that was not
    /// processed
    #[wasm_bindgen(readonly, js_name = "wireEvent")]
    pub wire_event: JsString,
    // TODO: Add some error information here?
}

#[wasm_bindgen]
impl DecryptedToDeviceEvent {
    /// Create a new `DecryptedToDeviceEvent`.
    #[wasm_bindgen(constructor)]
    pub fn new(wire_event: JsString, encryption_info: crate::responses::EncryptionInfo) -> Self {
        Self { processed_type: ProcessedToDeviceEventType::Decrypted, wire_event, encryption_info }
    }
}

#[wasm_bindgen]
impl PlainTextToDeviceEvent {
    /// Create a new `PlainTextToDeviceEvent`.
    #[wasm_bindgen(constructor)]
    pub fn new(wire_event: JsString) -> Self {
        Self { processed_type: ProcessedToDeviceEventType::PlainText, wire_event }
    }
}

#[wasm_bindgen]
impl UTDToDeviceEvent {
    /// Create a new `UTDToDeviceEvent`.
    #[wasm_bindgen(constructor)]
    pub fn new(wire_event: JsString) -> Self {
        Self { processed_type: ProcessedToDeviceEventType::UnableToDecrypt, wire_event }
    }
}
#[wasm_bindgen]
impl InvalidToDeviceEvent {
    /// Create a new `InvalidToDeviceEvent`.
    #[wasm_bindgen(constructor)]
    pub fn new(wire_event: JsString) -> Self {
        Self { processed_type: ProcessedToDeviceEventType::Invalid, wire_event }
    }
}

/// Convert an `ProcessedToDeviceEvent` into a `JsValue`, ready to return to
/// JavaScript.
///
/// JavaScript has no complex enums like Rust. To return structs of
/// different types, we have no choice that hiding everything behind a
/// `JsValue`.
pub fn processed_to_device_event_to_js_value(
    processed_to_device_event: matrix_sdk_crypto::types::ProcessedToDeviceEvent,
) -> JsValue {
    match processed_to_device_event {
        matrix_sdk_crypto::types::ProcessedToDeviceEvent::Decrypted { raw, encryption_info } => {
            JsValue::from(DecryptedToDeviceEvent {
                processed_type: ProcessedToDeviceEventType::Decrypted,
                wire_event: raw.json().get().to_owned().into(),
                encryption_info: encryption_info.into(),
            })
        }
        matrix_sdk_crypto::types::ProcessedToDeviceEvent::UnableToDecrypt(utd) => {
            JsValue::from(UTDToDeviceEvent::new(utd.json().get().to_owned().into()))
        }
        matrix_sdk_crypto::types::ProcessedToDeviceEvent::PlainText(plain) => {
            JsValue::from(PlainTextToDeviceEvent::new(plain.json().get().to_owned().into()))
        }
        matrix_sdk_crypto::types::ProcessedToDeviceEvent::Invalid(invalid) => {
            JsValue::from(InvalidToDeviceEvent::new(invalid.json().get().to_owned().into()))
        }
    }
}
