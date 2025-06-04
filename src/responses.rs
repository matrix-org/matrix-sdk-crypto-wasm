//! Types related to responses.

use js_sys::{Array, JsString};
pub(crate) use matrix_sdk_common::ruma::api::client::{
    backup::add_backup_keys::v3::Response as KeysBackupResponse,
    keys::{
        claim_keys::v3::Response as KeysClaimResponse, get_keys::v3::Response as KeysQueryResponse,
        upload_keys::v3::Response as KeysUploadResponse,
        upload_signatures::v3::Response as SignatureUploadResponse,
    },
    message::send_message_event::v3::Response as RoomMessageResponse,
    to_device::send_event_to_device::v3::Response as ToDeviceResponse,
};
use matrix_sdk_common::{
    deserialized_responses::AlgorithmInfo,
    ruma::{self, api::IncomingResponse as RumaIncomingResponse},
};
use matrix_sdk_crypto::types::requests::AnyIncomingResponse;
use wasm_bindgen::prelude::*;

use crate::{encryption, identifiers, impl_from_to_inner, requests::RequestType};
use crate::encryption::EncryptionAlgorithm;

pub(crate) fn response_from_string(body: &str) -> http::Result<http::Response<Vec<u8>>> {
    http::Response::builder().status(200).body(body.as_bytes().to_vec())
}

/// Intermediate private type to store an incoming owned response,
/// without the need to manage lifetime.
pub(crate) enum OwnedResponse {
    KeysUpload(KeysUploadResponse),
    KeysQuery(KeysQueryResponse),
    KeysClaim(KeysClaimResponse),
    ToDevice(ToDeviceResponse),
    SignatureUpload(SignatureUploadResponse),
    RoomMessage(RoomMessageResponse),
    KeysBackup(KeysBackupResponse),
}

impl From<KeysUploadResponse> for OwnedResponse {
    fn from(response: KeysUploadResponse) -> Self {
        OwnedResponse::KeysUpload(response)
    }
}

impl From<KeysQueryResponse> for OwnedResponse {
    fn from(response: KeysQueryResponse) -> Self {
        OwnedResponse::KeysQuery(response)
    }
}

impl From<KeysClaimResponse> for OwnedResponse {
    fn from(response: KeysClaimResponse) -> Self {
        OwnedResponse::KeysClaim(response)
    }
}

impl From<ToDeviceResponse> for OwnedResponse {
    fn from(response: ToDeviceResponse) -> Self {
        OwnedResponse::ToDevice(response)
    }
}

impl From<SignatureUploadResponse> for OwnedResponse {
    fn from(response: SignatureUploadResponse) -> Self {
        Self::SignatureUpload(response)
    }
}

impl From<RoomMessageResponse> for OwnedResponse {
    fn from(response: RoomMessageResponse) -> Self {
        OwnedResponse::RoomMessage(response)
    }
}

impl From<KeysBackupResponse> for OwnedResponse {
    fn from(r: KeysBackupResponse) -> Self {
        Self::KeysBackup(r)
    }
}

impl TryFrom<(RequestType, http::Response<Vec<u8>>)> for OwnedResponse {
    type Error = JsError;

    /// Convert an HTTP response object into the underlying ruma model of the
    /// response, and wrap as an OwnedResponse.
    ///
    /// (This is used in
    /// `matrix_sdk_crypto_js::OlmMachine::mark_request_as_sent`.)
    ///
    /// # Arguments
    ///
    /// * `request_type` - the type of the request that got this response
    /// * `response` - the raw HTTP response
    fn try_from(
        (request_type, response): (RequestType, http::Response<Vec<u8>>),
    ) -> Result<Self, Self::Error> {
        match request_type {
            RequestType::KeysUpload => {
                KeysUploadResponse::try_from_http_response(response).map(Into::into)
            }

            RequestType::KeysQuery => {
                KeysQueryResponse::try_from_http_response(response).map(Into::into)
            }

            RequestType::KeysClaim => {
                KeysClaimResponse::try_from_http_response(response).map(Into::into)
            }

            RequestType::ToDevice => {
                ToDeviceResponse::try_from_http_response(response).map(Into::into)
            }

            RequestType::SignatureUpload => {
                SignatureUploadResponse::try_from_http_response(response).map(Into::into)
            }

            RequestType::RoomMessage => {
                RoomMessageResponse::try_from_http_response(response).map(Into::into)
            }

            RequestType::KeysBackup => {
                KeysBackupResponse::try_from_http_response(response).map(Into::into)
            }
        }
        .map_err(JsError::from)
    }
}

// Make `OwnedResponse` implement `Into<AnyIncomingResponse>`.
//
// Required so that we can pass `OwnedResponse` into the real
// `matrix_sdk_crypto_js::OlmMachine::mark_request_as_sent`.
impl<'a> From<&'a OwnedResponse> for AnyIncomingResponse<'a> {
    fn from(response: &'a OwnedResponse) -> Self {
        match response {
            OwnedResponse::KeysUpload(response) => AnyIncomingResponse::KeysUpload(response),
            OwnedResponse::KeysQuery(response) => AnyIncomingResponse::KeysQuery(response),
            OwnedResponse::KeysClaim(response) => AnyIncomingResponse::KeysClaim(response),
            OwnedResponse::ToDevice(response) => AnyIncomingResponse::ToDevice(response),
            OwnedResponse::SignatureUpload(response) => {
                AnyIncomingResponse::SignatureUpload(response)
            }
            OwnedResponse::RoomMessage(response) => AnyIncomingResponse::RoomMessage(response),
            OwnedResponse::KeysBackup(response) => AnyIncomingResponse::KeysBackup(response),
        }
    }
}

/// A decrypted room event.
#[wasm_bindgen(getter_with_clone)]
#[derive(Debug)]
pub struct DecryptedRoomEvent {
    /// The JSON-encoded decrypted event.
    #[wasm_bindgen(readonly)]
    pub event: JsString,

    encryption_info: Option<EncryptionInfo>,
}

#[wasm_bindgen]
impl DecryptedRoomEvent {
    /// The user ID of the event sender, note this is untrusted data
    /// unless the `verification_state` is as well trusted.
    #[wasm_bindgen(getter)]
    pub fn sender(&self) -> Option<identifiers::UserId> {
        Some(self.encryption_info.as_ref()?.sender())
    }

    /// The device ID of the device that sent us the event, note this
    /// is untrusted data unless `verification_state` is as well
    /// trusted.
    #[wasm_bindgen(getter, js_name = "senderDevice")]
    pub fn sender_device(&self) -> Option<identifiers::DeviceId> {
        self.encryption_info.as_ref()?.sender_device()
    }

    /// The Curve25519 key of the device that created the megolm
    /// decryption key originally.
    #[wasm_bindgen(getter, js_name = "senderCurve25519Key")]
    pub fn sender_curve25519_key(&self) -> Option<JsString> {
        self.encryption_info.as_ref()?.sender_curve25519_key()
    }

    /// The signing Ed25519 key that have created the megolm key that
    /// was used to decrypt this session.
    #[wasm_bindgen(getter, js_name = "senderClaimedEd25519Key")]
    pub fn sender_claimed_ed25519_key(&self) -> Option<JsString> {
        self.encryption_info.as_ref()?.sender_claimed_ed25519_key()
    }

    /// Returns an empty array
    ///
    /// Previously, this returned the chain of Curve25519 keys through which
    /// this session was forwarded, via `m.forwarded_room_key` events.
    /// However, that is not cryptographically reliable, and clients should not
    /// be using it.
    ///
    /// @see https://github.com/matrix-org/matrix-spec/issues/1089
    #[wasm_bindgen(getter, js_name = "forwardingCurve25519KeyChain")]
    pub fn forwarding_curve25519_key_chain(&self) -> Array {
        Array::new()
    }

    /// The verification state of the device that sent us the event.
    /// Note this is the state of the device at the time of
    /// decryption. It may change in the future if a device gets
    /// verified or deleted.
    #[wasm_bindgen(js_name = "shieldState")]
    pub fn shield_state(&self, strict: bool) -> Option<encryption::ShieldState> {
        Some(self.encryption_info.as_ref()?.shield_state(strict))
    }
}

impl From<matrix_sdk_common::deserialized_responses::TimelineEvent> for DecryptedRoomEvent {
    fn from(value: matrix_sdk_common::deserialized_responses::TimelineEvent) -> Self {
        Self {
            event: value.raw().json().get().to_owned().into(),
            encryption_info: value.encryption_info().map(|e| e.as_ref().clone().into()),
        }
    }
}

/// Struct containing information on how an event was decrypted.
#[wasm_bindgen()]
#[derive(Debug, Clone)]
pub struct EncryptionInfo {
    inner: matrix_sdk_common::deserialized_responses::EncryptionInfo,
}

impl_from_to_inner!(matrix_sdk_common::deserialized_responses::EncryptionInfo => EncryptionInfo);

#[wasm_bindgen()]
impl EncryptionInfo {
    /// The user ID of the event sender. Note this is untrusted data
    /// unless `verification_state` is also trusted.
    #[wasm_bindgen(getter)]
    pub fn sender(&self) -> identifiers::UserId {
        identifiers::UserId::from(self.inner.sender.clone())
    }

    /// The device ID of the device that sent us the event. Note this
    /// is untrusted data unless `verification_state` is also
    /// trusted.
    #[wasm_bindgen(getter, js_name = "senderDevice")]
    pub fn sender_device(&self) -> Option<identifiers::DeviceId> {
        Some(self.inner.sender_device.as_ref()?.clone().into())
    }

    /// The Curve25519 key of the device that created the megolm
    /// decryption key originally.
    #[wasm_bindgen(getter, js_name = "senderCurve25519Key")]
    pub fn sender_curve25519_key(&self) -> Option<JsString> {
        match &self.inner.algorithm_info {
            AlgorithmInfo::MegolmV1AesSha2 { curve25519_key, .. } => {
                Some(curve25519_key.clone().into())
            }
            AlgorithmInfo::OlmV1Curve25519AesSha2 { curve25519_public_key_base64 } => {
                Some(curve25519_public_key_base64.clone().into())
            }
        }
    }

    /// The signing Ed25519 key that created the megolm key that
    /// was used to decrypt this session.
    #[wasm_bindgen(getter, js_name = "senderClaimedEd25519Key")]
    pub fn sender_claimed_ed25519_key(&self) -> Option<JsString> {
        match &self.inner.algorithm_info {
            AlgorithmInfo::MegolmV1AesSha2 { sender_claimed_keys, .. } => {
                sender_claimed_keys.get(&ruma::DeviceKeyAlgorithm::Ed25519).cloned().map(Into::into)
            }
            // Not applicable for olm info
            AlgorithmInfo::OlmV1Curve25519AesSha2 { .. } => None,
        }
    }

    /// The verification state of the device that sent us the event.
    /// Note this is the state of the device at the time of
    /// decryption. It may change in the future if a device gets
    /// verified or deleted.
    ///
    /// # Arguments
    ///
    /// * `strict` - whether to enable "strict mode" verification. In non-strict
    ///   mode, unverified users are given no shield, and keys that have been
    ///   forwarded or restored from an insecure backup are given a grey shield
    ///   (both get a red shield in strict mode).
    #[wasm_bindgen(js_name = "shieldState")]
    pub fn shield_state(&self, strict: bool) -> encryption::ShieldState {
        let verification_state = &self.inner.verification_state;

        if strict {
            verification_state.to_shield_state_strict()
        } else {
            verification_state.to_shield_state_lax()
        }
        .into()
    }

    /// Get the algorithm used for encryption.
    #[wasm_bindgen(getter, js_name = "algorithm")]
    pub fn algorithm(&self) -> EncryptionAlgorithm {
        match self.inner.algorithm_info {
            AlgorithmInfo::MegolmV1AesSha2 { .. } => EncryptionAlgorithm::MegolmV1AesSha2,
            AlgorithmInfo::OlmV1Curve25519AesSha2 { .. } => EncryptionAlgorithm::OlmV1Curve25519AesSha2
        }
    }
}
