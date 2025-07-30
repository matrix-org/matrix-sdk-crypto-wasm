//! Types to handle requests.

use std::time::Duration;

use js_sys::JsString;
use matrix_sdk_common::ruma::{
    api::client::{
        dehydrated_device::put_dehydrated_device::unstable::Request as OriginalPutDehydratedDeviceRequest,
        keys::{
            claim_keys::v3::Request as OriginalKeysClaimRequest,
            upload_keys::v3::Request as OriginalKeysUploadRequest,
            upload_signatures::v3::Request as OriginalSignatureUploadRequest,
        },
    },
    events::MessageLikeEventContent,
    exports::serde::ser::Error,
};
use matrix_sdk_crypto::{
    types::requests::{
        AnyOutgoingRequest, KeysBackupRequest as OriginalKeysBackupRequest,
        KeysQueryRequest as OriginalKeysQueryRequest,
        RoomMessageRequest as OriginalRoomMessageRequest,
        ToDeviceRequest as OriginalToDeviceRequest,
        UploadSigningKeysRequest as OriginalUploadSigningKeysRequest,
    },
    CrossSigningBootstrapRequests as OriginalCrossSigningBootstrapRequests,
};
use wasm_bindgen::prelude::*;

/** Outgoing Requests * */

/// Data for a request to the `/keys/upload` API endpoint
/// ([specification]).
///
/// Publishes end-to-end encryption keys for the device.
///
/// [specification]: https://spec.matrix.org/unstable/client-server-api/#post_matrixclientv3keysupload
#[derive(Debug)]
#[wasm_bindgen(getter_with_clone)]
pub struct KeysUploadRequest {
    /// The request ID.
    #[wasm_bindgen(readonly)]
    pub id: JsString,

    /// A JSON-encoded object containing the rest of the payload: `device_keys`,
    /// `one_time_keys`, `fallback_keys`.
    ///
    /// It represents the body of the HTTP request.
    #[wasm_bindgen(readonly)]
    pub body: JsString,
}

#[wasm_bindgen]
impl KeysUploadRequest {
    /// Create a new `KeysUploadRequest`.
    #[wasm_bindgen(constructor)]
    pub fn new(id: JsString, body: JsString) -> KeysUploadRequest {
        Self { id, body }
    }

    /// Get its request type.
    #[wasm_bindgen(getter, js_name = "type")]
    pub fn request_type(&self) -> RequestType {
        RequestType::KeysUpload
    }
}

/// Data for a request to the `/keys/query` API endpoint
/// ([specification]).
///
/// Returns the current devices and identity keys for the given users.
///
/// [specification]: https://spec.matrix.org/unstable/client-server-api/#post_matrixclientv3keysquery
#[derive(Debug)]
#[wasm_bindgen(getter_with_clone)]
pub struct KeysQueryRequest {
    /// The request ID.
    #[wasm_bindgen(readonly)]
    pub id: JsString,

    /// A JSON-encoded object containing the rest of the payload: `timeout`,
    /// `device_keys`, `token`.
    ///
    /// It represents the body of the HTTP request.
    #[wasm_bindgen(readonly)]
    pub body: JsString,
}

#[wasm_bindgen]
impl KeysQueryRequest {
    /// Create a new `KeysQueryRequest`.
    #[wasm_bindgen(constructor)]
    pub fn new(id: JsString, body: JsString) -> KeysQueryRequest {
        Self { id, body }
    }

    /// Get its request type.
    #[wasm_bindgen(getter, js_name = "type")]
    pub fn request_type(&self) -> RequestType {
        RequestType::KeysQuery
    }
}

/// Data for a request to the `/keys/claim` API endpoint
/// ([specification]).
///
/// Claims one-time keys that can be used to establish 1-to-1 E2EE
/// sessions.
///
/// [specification]: https://spec.matrix.org/unstable/client-server-api/#post_matrixclientv3keysclaim
#[derive(Debug)]
#[wasm_bindgen(getter_with_clone)]
pub struct KeysClaimRequest {
    /// The request ID.
    #[wasm_bindgen(readonly)]
    pub id: JsString,

    /// A JSON-encoded object containing the rest of the payload: `timeout`,
    /// `one_time_keys`.
    ///
    /// It represents the body of the HTTP request.
    #[wasm_bindgen(readonly)]
    pub body: JsString,
}

#[wasm_bindgen]
impl KeysClaimRequest {
    /// Create a new `KeysClaimRequest`.
    #[wasm_bindgen(constructor)]
    pub fn new(id: JsString, body: JsString) -> KeysClaimRequest {
        Self { id, body }
    }

    /// Get its request type.
    #[wasm_bindgen(getter, js_name = "type")]
    pub fn request_type(&self) -> RequestType {
        RequestType::KeysClaim
    }
}

/// Data for a request to the `/sendToDevice` API endpoint
/// ([specification]).
///
/// Send an event to a single device or to a group of devices.
///
/// [specification]: https://spec.matrix.org/unstable/client-server-api/#put_matrixclientv3sendtodeviceeventtypetxnid
#[derive(Debug)]
#[wasm_bindgen(getter_with_clone)]
pub struct ToDeviceRequest {
    /// The request ID.
    /// For to-device request this would be the same value as `txn_id`. It is
    /// exposed also as `id` so that the js bindings are consistent with the
    /// other request types by using this field to mark as sent.
    #[wasm_bindgen(readonly)]
    pub id: JsString,

    /// A string representing the type of event being sent to each devices.
    #[wasm_bindgen(readonly)]
    pub event_type: JsString,

    /// A string representing a request identifier unique to the access token
    /// used to send the request.
    #[wasm_bindgen(readonly)]
    pub txn_id: JsString,

    /// A JSON-encoded object containing the rest of the payload: `messages`.
    ///
    /// It represents the body of the HTTP request.
    #[wasm_bindgen(readonly)]
    pub body: JsString,
}

#[wasm_bindgen]
impl ToDeviceRequest {
    /// Create a new `ToDeviceRequest`.
    #[wasm_bindgen(constructor)]
    pub fn new(
        id: JsString,
        event_type: JsString,
        txn_id: JsString,
        body: JsString,
    ) -> ToDeviceRequest {
        Self { id, event_type, txn_id, body }
    }

    /// Get its request type.
    #[wasm_bindgen(getter, js_name = "type")]
    pub fn request_type(&self) -> RequestType {
        RequestType::ToDevice
    }
}

/// Data for a request to the `/keys/signatures/upload` API endpoint
/// ([specification]).
///
/// Publishes cross-signing signatures for the user.
///
/// [specification]: https://spec.matrix.org/unstable/client-server-api/#post_matrixclientv3keyssignaturesupload
#[derive(Debug, Clone)]
#[wasm_bindgen(getter_with_clone)]
pub struct SignatureUploadRequest {
    /// The request ID.
    /// Some signature upload will have to an `id` field, some won't.
    /// They have one when they are created automatically during an interactive
    /// verification, otherwise they don't.
    #[wasm_bindgen(readonly)]
    pub id: Option<JsString>,

    /// A JSON-encoded object containing the payload of the request
    ///
    /// It represents the body of the HTTP request.
    #[wasm_bindgen(readonly, js_name = "body")]
    pub signed_keys: JsString,
}

#[wasm_bindgen]
impl SignatureUploadRequest {
    /// Create a new `SignatureUploadRequest`.
    #[wasm_bindgen(constructor)]
    pub fn new(id: JsString, signed_keys: JsString) -> SignatureUploadRequest {
        Self { id: Some(id), signed_keys }
    }

    /// Get its request type.
    #[wasm_bindgen(getter, js_name = "type")]
    pub fn request_type(&self) -> RequestType {
        RequestType::SignatureUpload
    }
}

/// A customized owned request type for sending out room messages
/// ([specification]).
///
/// [specification]: https://spec.matrix.org/unstable/client-server-api/#put_matrixclientv3roomsroomidsendeventtypetxnid
#[derive(Debug)]
#[wasm_bindgen(getter_with_clone)]
pub struct RoomMessageRequest {
    /// The request ID.
    #[wasm_bindgen(readonly)]
    pub id: JsString,

    /// A string representing the room to send the event to.
    #[wasm_bindgen(readonly)]
    pub room_id: JsString,

    /// A string representing the transaction ID for this event.
    ///
    /// Clients should generate an ID unique across requests with the same
    /// access token; it will be used by the server to ensure idempotency of
    /// requests.
    #[wasm_bindgen(readonly)]
    pub txn_id: JsString,

    /// A string representing the type of event to be sent.
    #[wasm_bindgen(readonly)]
    pub event_type: JsString,

    /// A JSON-encoded object containing the message's content.
    #[wasm_bindgen(readonly, js_name = "body")]
    pub content: JsString,
}

#[wasm_bindgen]
impl RoomMessageRequest {
    /// Create a new `RoomMessageRequest`.
    #[wasm_bindgen(constructor)]
    pub fn new(
        id: JsString,
        room_id: JsString,
        txn_id: JsString,
        event_type: JsString,
        content: JsString,
    ) -> RoomMessageRequest {
        Self { id, room_id, txn_id, event_type, content }
    }

    /// Get its request type.
    #[wasm_bindgen(getter, js_name = "type")]
    pub fn request_type(&self) -> RequestType {
        RequestType::RoomMessage
    }
}

/// A request that will back up a batch of room keys to the server
/// ([specification]).
///
/// [specification]: https://spec.matrix.org/unstable/client-server-api/#put_matrixclientv3room_keyskeys
#[derive(Debug)]
#[wasm_bindgen(getter_with_clone)]
pub struct KeysBackupRequest {
    /// The request ID.
    #[wasm_bindgen(readonly)]
    pub id: JsString,

    /// A JSON-encoded object containing the rest of the payload: `rooms`.
    ///
    /// It represents the body of the HTTP request.
    #[wasm_bindgen(readonly)]
    pub body: JsString,

    /// The backup version that these room keys should be part of.
    #[wasm_bindgen(readonly)]
    pub version: JsString,
}

#[wasm_bindgen]
impl KeysBackupRequest {
    /// Create a new `KeysBackupRequest`.
    #[wasm_bindgen(constructor)]
    pub fn new(id: JsString, body: JsString, version: JsString) -> KeysBackupRequest {
        Self { id, body, version }
    }

    /// Get its request type.
    #[wasm_bindgen(getter, js_name = "type")]
    pub fn request_type(&self) -> RequestType {
        RequestType::KeysBackup
    }
}

macro_rules! request {
    (
        $destination_request:ident from $source_request:ident
        $( extracts $( $field_name:ident : $field_type:tt ),+ $(,)? )?
        $( $( and )? groups $( $grouped_field_name:ident $( { $transformation:expr } )? $( $optional:literal )? ),+ $(,)? )?
    ) => {

        impl TryFrom<(String, &$source_request)> for $destination_request {
            type Error = serde_json::Error;

            fn try_from(
                (request_id, request): (String, &$source_request),
            ) -> Result<Self, Self::Error> {
                request!(
                    @__try_from $destination_request from $source_request
                    (request_id = request_id.into(), request = request)
                    $( extracts [ $( $field_name : $field_type, )+ ] )?
                    $( groups [ $( $grouped_field_name $( { $transformation } )? $( $optional )? , )+ ] )?
                )
            }
        }
    };

    (
        @__try_from $destination_request:ident from $source_request:ident
        (request_id = $request_id:expr, request = $request:expr)
        $( extracts [ $( $field_name:ident : $field_type:tt ),* $(,)? ] )?
        $( groups [ $( $grouped_field_name:ident $( { $transformation:expr } )? $( $optional:literal )? ),* $(,)? ] )?
    ) => {
        {
            Ok($destination_request {
                id: $request_id,
                $(
                    $(
                        $field_name: request!(@__field $field_name : $field_type ; request = $request),
                    )*
                )?
                $(
                    body: {
                        let mut map = serde_json::Map::new();
                        $(
                            let field = &$request.$grouped_field_name;
                            $(
                                let field = {
                                    let $grouped_field_name = field;

                                    $transformation
                                };
                            )?
                            request!(@__set_field $( $optional )? map : $grouped_field_name = field);
                        )*
                        let object = serde_json::Value::Object(map);

                        serde_json::to_string(&object)?.into()
                    }
                )?
            })
        }
    };

    ( @__field $field_name:ident : $field_type:ident ; request = $request:expr ) => {
        request!(@__field_type as $field_type ; request = $request, field_name = $field_name)
    };

    ( @__field_type as string ; request = $request:expr, field_name = $field_name:ident ) => {
        $request.$field_name.to_string().into()
    };

    ( @__field_type as json ; request = $request:expr, field_name = $field_name:ident ) => {
        serde_json::to_string(&$request.$field_name)?.into()
    };

    ( @__field_type as event_type ; request = $request:expr, field_name = $field_name:ident ) => {
        $request.content.event_type().to_string().into()
    };

    ( @__set_field $optional:literal $map:ident : $grouped_field_name:ident = $field:ident) => {
        if let Some($field) = $field {
            request!(@__set_field $map : $grouped_field_name = $field);
        }
    };

    ( @__set_field $map:ident : $grouped_field_name:ident = $field:ident) => {
        $map.insert(stringify!($grouped_field_name).to_owned(), serde_json::to_value($field).unwrap());
    };
}

// Generate the methods needed to convert rust `AnyOutgoingRequest` into the js
// counterpart. Technically it's converting tuples `(String, &Original)`, where
// the first member  is the request ID, into js requests. Used by
// `TryFrom<OutgoingRequest> for JsValue`.
request!(KeysUploadRequest from OriginalKeysUploadRequest groups device_keys "optional", one_time_keys, fallback_keys);
request!(KeysQueryRequest from OriginalKeysQueryRequest groups timeout { timeout.as_ref().map(Duration::as_millis).map(u64::try_from).transpose().map_err(serde_json::Error::custom)? } "optional", device_keys);
request!(KeysClaimRequest from OriginalKeysClaimRequest groups timeout { timeout.as_ref().map(Duration::as_millis).map(u64::try_from).transpose().map_err(serde_json::Error::custom)? } "optional", one_time_keys);
request!(ToDeviceRequest from OriginalToDeviceRequest extracts event_type: string, txn_id: string and groups messages);
request!(RoomMessageRequest from OriginalRoomMessageRequest extracts room_id: string, txn_id: string, event_type: event_type, content: json);
request!(KeysBackupRequest from OriginalKeysBackupRequest extracts version: string and groups rooms);

// Specific conversion for signature upload as they can be returned directly by
// some verification API and not via `outgoing_requests()`. If returned by
// `outgoing_requests()` they would need to be marked as sent using `id`,
// otherwise no need to mark them as sent. This is why `SignatureUploadRequest`
// has an optional `id` field. It is set to some when converting from
// `OutgoingRequest`, and to None if not.
impl TryFrom<&OriginalSignatureUploadRequest> for SignatureUploadRequest {
    type Error = serde_json::Error;
    fn try_from(request: &OriginalSignatureUploadRequest) -> Result<Self, Self::Error> {
        {
            Ok(SignatureUploadRequest {
                id: None,
                signed_keys: serde_json::to_string(&request.signed_keys)?.into(),
            })
        }
    }
}

// Manual into/from for signature upload requests as the id is optional.
impl TryFrom<(String, &OriginalSignatureUploadRequest)> for SignatureUploadRequest {
    type Error = serde_json::Error;
    fn try_from(
        (request_id, request): (String, &OriginalSignatureUploadRequest),
    ) -> Result<Self, Self::Error> {
        {
            Ok(SignatureUploadRequest {
                id: Some(request_id.into()),
                signed_keys: serde_json::to_string(&request.signed_keys)?.into(),
            })
        }
    }
}

// ToDeviceRequests can be returned directly from `OlmMachine::share_room_key`,
// instead of being wrapped in a `matrix_sdk_crypto::OutgoingRequest` via
// `OlmMachine::outgoing_requests`.
//
// We therefore need a custom conversion implementation to deal with that case.
impl TryFrom<&OriginalToDeviceRequest> for ToDeviceRequest {
    type Error = serde_json::Error;
    fn try_from(request: &OriginalToDeviceRequest) -> Result<Self, Self::Error> {
        {
            Ok(ToDeviceRequest {
                // When matrix_sdk_crypto returns requests via `share_room_key`, they must be sent
                // out to the server and the responses need to be passed back to the
                // olmMachine using [`mark_request_as_sent`], using the `txn_id` as
                // `request_id`
                id: request.txn_id.to_string().into(),
                event_type: request.event_type.to_string().into(),
                txn_id: request.txn_id.to_string().into(),
                body: {
                    let mut map = serde_json::Map::new();
                    map.insert(
                        "messages".to_owned(),
                        serde_json::to_value(&request.messages).unwrap(),
                    );
                    let object = serde_json::Value::Object(map);
                    serde_json::to_string(&object)?.into()
                },
            })
        }
    }
}

/// Convert an `OutgoingRequest` into a `JsValue`, ready to return to
/// JavaScript.
///
/// JavaScript has no complex enums like Rust. To return structs of
/// different types, we have no choice that hiding everything behind a
/// `JsValue`.
pub fn outgoing_request_to_js_value(
    outgoing_request: matrix_sdk_crypto::types::requests::OutgoingRequest,
) -> Result<JsValue, serde_json::Error> {
    let request_id = outgoing_request.request_id().to_string();

    Ok(match outgoing_request.request() {
        AnyOutgoingRequest::KeysUpload(request) => {
            JsValue::from(KeysUploadRequest::try_from((request_id, request))?)
        }

        AnyOutgoingRequest::KeysQuery(request) => {
            JsValue::from(KeysQueryRequest::try_from((request_id, request))?)
        }

        AnyOutgoingRequest::KeysClaim(request) => {
            JsValue::from(KeysClaimRequest::try_from((request_id, request))?)
        }

        AnyOutgoingRequest::ToDeviceRequest(request) => {
            JsValue::from(ToDeviceRequest::try_from((request_id, request))?)
        }

        AnyOutgoingRequest::SignatureUpload(request) => {
            JsValue::from(SignatureUploadRequest::try_from((request_id, request))?)
        }

        AnyOutgoingRequest::RoomMessage(request) => {
            JsValue::from(RoomMessageRequest::try_from((request_id, request.as_ref()))?)
        }
    })
}

/// Represent the type of a request.
#[wasm_bindgen]
#[derive(Debug)]
pub enum RequestType {
    /// Represents a `KeysUploadRequest`.
    KeysUpload,

    /// Represents a `KeysQueryRequest`.
    KeysQuery,

    /// Represents a `KeysClaimRequest`.
    KeysClaim,

    /// Represents a `ToDeviceRequest`.
    ToDevice,

    /// Represents a `SignatureUploadRequest`.
    SignatureUpload,

    /// Represents a `RoomMessageRequest`.
    RoomMessage,

    /// Represents a `KeysBackupRequest`.
    KeysBackup,
}

/** Other Requests * */

/// Request that will publish a cross signing identity.
///
/// This uploads the public cross signing key triplet.
#[wasm_bindgen(getter_with_clone)]
#[derive(Debug, Clone)]
pub struct UploadSigningKeysRequest {
    /// A JSON-encoded object containing the rest of the payload: `master_key`,
    /// `self_signing_key`, `user_signing_key`.
    ///
    /// It represents the body of the HTTP request.
    #[wasm_bindgen(readonly)]
    pub body: JsString,
}

#[wasm_bindgen]
impl UploadSigningKeysRequest {
    /// Create a new `UploadSigningKeysRequest`.
    #[wasm_bindgen(constructor)]
    pub fn new(body: JsString) -> UploadSigningKeysRequest {
        Self { body }
    }
}

impl TryFrom<&OriginalUploadSigningKeysRequest> for UploadSigningKeysRequest {
    type Error = serde_json::Error;
    fn try_from(request: &OriginalUploadSigningKeysRequest) -> Result<Self, Self::Error> {
        {
            Ok(UploadSigningKeysRequest {
                body: {
                    let mut map = serde_json::Map::new();
                    map.insert(
                        "master_key".to_owned(),
                        serde_json::to_value(&request.master_key).unwrap(),
                    );
                    map.insert(
                        "self_signing_key".to_owned(),
                        serde_json::to_value(&request.self_signing_key).unwrap(),
                    );
                    map.insert(
                        "user_signing_key".to_owned(),
                        serde_json::to_value(&request.user_signing_key).unwrap(),
                    );
                    let object = serde_json::Value::Object(map);
                    serde_json::to_string(&object)?.into()
                },
            })
        }
    }
}

#[wasm_bindgen(getter_with_clone)]
#[derive(Debug)]
/// A request that will upload a dehydrated device to the server.
pub struct PutDehydratedDeviceRequest {
    /// A JSON-encoded object containing the rest of the payload: `rooms`.
    ///
    /// It represents the body of the HTTP request.
    #[wasm_bindgen(readonly)]
    pub body: JsString,
}

#[wasm_bindgen]
impl PutDehydratedDeviceRequest {
    /// Create a new `PutDehydratedDeviceRequest`
    #[wasm_bindgen(constructor)]
    pub fn new(body: JsString) -> PutDehydratedDeviceRequest {
        Self { body }
    }
}

impl TryFrom<OriginalPutDehydratedDeviceRequest> for PutDehydratedDeviceRequest {
    type Error = serde_json::Error;
    fn try_from(request: OriginalPutDehydratedDeviceRequest) -> Result<Self, Self::Error> {
        Ok(Self {
            body: {
                let mut map = serde_json::Map::new();
                map.insert(
                    "device_id".to_owned(),
                    serde_json::to_value(&request.device_id).unwrap(),
                );
                if let Some(initial_device_display_name) = request.initial_device_display_name {
                    map.insert(
                        "initial_device_display_name".to_owned(),
                        serde_json::to_value(&initial_device_display_name).unwrap(),
                    );
                }
                map.insert(
                    "device_data".to_owned(),
                    serde_json::to_value(&request.device_data).unwrap(),
                );
                map.insert(
                    "device_keys".to_owned(),
                    serde_json::to_value(&request.device_keys).unwrap(),
                );
                if !request.one_time_keys.is_empty() {
                    map.insert(
                        "one_time_keys".to_owned(),
                        serde_json::to_value(&request.one_time_keys).unwrap(),
                    );
                }
                if !request.fallback_keys.is_empty() {
                    map.insert(
                        "fallback_keys".to_owned(),
                        serde_json::to_value(&request.fallback_keys).unwrap(),
                    );
                }
                let object = serde_json::Value::Object(map);
                serde_json::to_string(&object)?.into()
            },
        })
    }
}

/// A set of requests to be executed when bootstrapping cross-signing using
/// {@link OlmMachine.bootstrapCrossSigning}.
#[wasm_bindgen(getter_with_clone)]
#[derive(Debug)]
pub struct CrossSigningBootstrapRequests {
    /// An optional request to upload a device key.
    ///
    /// This will either be `undefined`, or an "outgoing request" as returned by
    /// {@link OlmMachine.outgoingRequests}.
    ///
    /// If it is defined, the request should be sent first, and the result sent
    /// back with {@link OlmMachine.markRequestAsSent}.
    #[wasm_bindgen(readonly, js_name = "uploadKeysRequest")]
    pub upload_keys_request: JsValue,

    /// Request to upload the cross-signing keys.
    ///
    /// Should be sent second.
    #[wasm_bindgen(readonly, js_name = "uploadSigningKeysRequest")]
    pub upload_signing_keys_request: UploadSigningKeysRequest,

    /// Request to upload key signatures, including those for the cross-signing
    /// keys, and maybe some for the optional uploaded key too.
    ///
    /// Should be sent last.
    #[wasm_bindgen(readonly, js_name = "uploadSignaturesRequest")]
    pub upload_signatures_request: SignatureUploadRequest,
}

impl TryFrom<OriginalCrossSigningBootstrapRequests> for CrossSigningBootstrapRequests {
    type Error = serde_json::Error;
    fn try_from(request: OriginalCrossSigningBootstrapRequests) -> Result<Self, Self::Error> {
        Ok(CrossSigningBootstrapRequests {
            upload_keys_request: request
                .upload_keys_req
                .map(outgoing_request_to_js_value)
                .transpose()?
                .into(),
            upload_signing_keys_request: (&request.upload_signing_keys_req).try_into()?,
            upload_signatures_request: (&request.upload_signatures_req).try_into()?,
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::collections::BTreeMap;

    use matrix_sdk_common::ruma::{
        api::client::keys::{
            claim_keys::v3::Request as OriginalKeysClaimRequest,
            upload_keys::v3::Request as OriginalKeysUploadRequest,
        },
        device_id, user_id, OneTimeKeyAlgorithm,
    };
    use matrix_sdk_crypto::types::requests::KeysQueryRequest as OriginalKeysQueryRequest;
    use serde_json::Value;
    use wasm_bindgen_test::wasm_bindgen_test;
    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_node_experimental);

    use super::{KeysClaimRequest, KeysQueryRequest, KeysUploadRequest};

    #[wasm_bindgen_test]
    // make sure that the timeout in a /keys/claim request is encoded as a number
    fn test_keys_claim_request_with_timeout() {
        let rust_request = OriginalKeysClaimRequest::new(BTreeMap::from([(
            user_id!("@alice:localhost").to_owned(),
            BTreeMap::from([(
                device_id!("ABCDEFG").to_owned(),
                OneTimeKeyAlgorithm::SignedCurve25519,
            )]),
        )]));
        let request = KeysClaimRequest::try_from(("ID".to_string(), &rust_request)).unwrap();
        let body: Value = serde_json::from_str(&String::from(request.body)).unwrap();
        assert!(body.as_object().unwrap().contains_key("timeout"));
        assert!(body["timeout"].is_number());
    }

    #[wasm_bindgen_test]
    // if a /keys/claim request has no timeout, make sure it isn't in the request
    fn test_keys_claim_request_without_timeout() {
        let mut rust_request = OriginalKeysClaimRequest::new(BTreeMap::from([(
            user_id!("@alice:localhost").to_owned(),
            BTreeMap::from([(
                device_id!("ABCDEFG").to_owned(),
                OneTimeKeyAlgorithm::SignedCurve25519,
            )]),
        )]));
        rust_request.timeout = None;
        let request = KeysClaimRequest::try_from(("ID".to_string(), &rust_request)).unwrap();
        let body: Value = serde_json::from_str(&String::from(request.body)).unwrap();
        assert!(!body.as_object().unwrap().contains_key("timeout"));
    }

    #[wasm_bindgen_test]
    // make sure that the timeout is encoded as a number in a /keys/query
    fn test_keys_query_request_with_timeout() {
        let rust_request = OriginalKeysQueryRequest {
            timeout: Some(std::time::Duration::from_secs(10)),
            device_keys: BTreeMap::new(),
        };
        let request = KeysQueryRequest::try_from(("ID".to_string(), &rust_request)).unwrap();
        let body: Value = serde_json::from_str(&String::from(request.body)).unwrap();
        assert!(body.as_object().unwrap().contains_key("timeout"));
        assert!(body["timeout"].is_number());
    }

    #[wasm_bindgen_test]
    // if a /keys/query request has no timeout, make sure it isn't in the request
    fn test_keys_query_request_without_timeout() {
        let rust_request = OriginalKeysQueryRequest { timeout: None, device_keys: BTreeMap::new() };
        let request = KeysQueryRequest::try_from(("ID".to_string(), &rust_request)).unwrap();
        let body: Value = serde_json::from_str(&String::from(request.body)).unwrap();
        assert!(!body.as_object().unwrap().contains_key("timeout"));
    }

    #[wasm_bindgen_test]
    // if a /keys/upload request no device_keys, make sure it isn't in the request
    fn test_keys_upload_request_without_devices() {
        let request = OriginalKeysUploadRequest::new();
        let request = KeysUploadRequest::try_from(("ID".to_string(), &request)).unwrap();
        let body: Value = serde_json::from_str(&String::from(request.body)).unwrap();
        assert!(!body.as_object().unwrap().contains_key("device_keys"));
    }
}
