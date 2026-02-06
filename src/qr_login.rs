//! Types for QR code login

use matrix_sdk_crypto::types::qr_login;
use url::Url;
use wasm_bindgen::prelude::*;

use crate::vodozemac::Curve25519PublicKey;

/// The mode of the QR code login.
///
/// The QR code login mechanism supports both, the new device, as well as the
/// existing device to display the QR code.
///
/// The different modes have an explicit one-byte identifier which gets added to
/// the QR code data.
#[wasm_bindgen]
#[derive(Debug)]
pub enum QrCodeIntent {
    /// The new device is displaying the QR code.
    Login,
    /// The existing device is displaying the QR code.
    Reciprocate,
}

impl From<qr_login::QrCodeIntent> for QrCodeIntent {
    fn from(value: qr_login::QrCodeIntent) -> Self {
        match value {
            qr_login::QrCodeIntent::Login => Self::Login,
            qr_login::QrCodeIntent::Reciprocate => Self::Reciprocate,
        }
    }
}

impl Into<qr_login::QrCodeIntent> for QrCodeIntent {
    fn into(self) -> qr_login::QrCodeIntent {
        match self {
            QrCodeIntent::Login => qr_login::QrCodeIntent::Login,
            QrCodeIntent::Reciprocate => qr_login::QrCodeIntent::Reciprocate,
        }
    }
}

/// Intent and MSC-specific data class for the QR code login support.
#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct QrCodeIntentData {
    /// The MSC4108-specific intent data.
    ///
    /// This will not be `null` only if the {@link QrCodeData} contains data as
    /// specified in the QR code format of MSC4108. Otherwise it will contain
    /// MSC4388-specific intent data.
    #[wasm_bindgen(getter_with_clone, js_name = "msc4108")]
    pub msc_4108: Option<Msc4108IntentData>,

    /// The MSC4833-specific intent data.
    ///
    /// This will not be `null` only if the {@link QrCodeData} contains data as
    /// specified in the QR code format of MSC4388. Otherwise it will contain
    /// MSC4108-specific intent data.
    #[wasm_bindgen(getter_with_clone, js_name = "msc4388")]
    pub msc_4388: Option<Msc4388IntentData>,
}

impl From<qr_login::QrCodeIntentData<'_>> for QrCodeIntentData {
    fn from(value: qr_login::QrCodeIntentData) -> Self {
        match value {
            qr_login::QrCodeIntentData::Msc4108 { data, rendezvous_url } => {
                let server_name = match data {
                    qr_login::Msc4108IntentData::Login => None,
                    qr_login::Msc4108IntentData::Reciprocate { server_name } => {
                        Some(server_name.to_owned())
                    }
                };

                Self {
                    msc_4108: Some(Msc4108IntentData {
                        rendezvous_url: rendezvous_url.to_string(),
                        server_name,
                    }),
                    msc_4388: None,
                }
            }
            qr_login::QrCodeIntentData::Msc4388 { rendezvous_id, base_url } => Self {
                msc_4108: None,
                msc_4388: Some(Msc4388IntentData {
                    rendezvous_id: rendezvous_id.to_owned(),
                    base_url: base_url.to_string(),
                }),
            },
        }
    }
}

/// Intent-specific data in the case the QR code adheres to
/// {@link https://github.com/matrix-org/matrix-spec-proposals/pull/4108 MSC4108} of the QR code
/// data format.
#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct Msc4108IntentData {
    /// Get the URL of the rendezvous server which will be used to exchange
    /// messages between the two devices.
    #[wasm_bindgen(getter_with_clone, js_name = "rendezvousUrl")]
    pub rendezvous_url: String,

    /// Get the server name of the homeserver which the new device will be
    /// logged in to.
    ///
    /// This will be only available if the existing device has generated the QR
    /// code and the new device is the one scanning the QR code.
    #[wasm_bindgen(getter_with_clone, js_name = "serverName")]
    pub server_name: Option<String>,
}

/// Intent-specific data in the case the QR code adheres to
/// {@link https://github.com/matrix-org/matrix-spec-proposals/pull/4388 MSC4388} of the QR code
/// data format.
#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct Msc4388IntentData {
    /// The ID of the rendezvous session, can be used to exchange messages with
    /// the other device.
    #[wasm_bindgen(getter_with_clone, js_name = "rendezvousId")]
    pub rendezvous_id: String,

    /// The base URL of the homeserver that the device generating the QR is
    /// using.
    #[wasm_bindgen(getter_with_clone, js_name = "baseUrl")]
    pub base_url: String,
}

/// Data for the QR code login mechanism.
///
/// The {@link QrCodeData} can be serialized and encoded as a QR code or it can
/// be decoded from a QR code.
///
/// This type supports both the format originally speicied in
/// {link https://github.com/matrix-org/matrix-spec-proposals/pull/4108 MSC4108} as well as the
/// updated format found in
/// {link https://github.com/matrix-org/matrix-spec-proposals/pull/4388 MSC4388}.
#[wasm_bindgen]
#[derive(Debug)]
pub struct QrCodeData {
    inner: qr_login::QrCodeData,
}

#[wasm_bindgen]
impl QrCodeData {
    /// Create new {@link QrCodeData} from a given public key, a rendezvous URL
    /// and, optionally, a server name for the homeserver.
    ///
    /// If a server name is given, then the {@link QrCodeData} mode will be
    /// {@link QrCodeIntent.Reciprocate}, i.e. the QR code will contain data for
    /// the existing device to display the QR code.
    ///
    /// If no server name is given, the {@link QrCodeData} mode will be
    /// {@link QrCodeIntent.Login}, i.e. the QR code will contain data for the
    /// new device to display the QR code.
    #[wasm_bindgen(constructor)]
    pub fn new(
        public_key: Curve25519PublicKey,
        rendezvous_url: &str,
        server_name: Option<String>,
    ) -> Result<QrCodeData, JsError> {
        let public_key = public_key.inner;
        let rendezvous_url = Url::parse(rendezvous_url)?;

        let intent_data = if let Some(server_name) = server_name {
            qr_login::Msc4108IntentData::Reciprocate { server_name }
        } else {
            qr_login::Msc4108IntentData::Login
        };

        let inner = qr_login::QrCodeData::new_msc4108(public_key, rendezvous_url, intent_data);

        Ok(QrCodeData { inner })
    }

    /// Create new {@link QrCodeData} from a given public key, a rendezvous ID
    /// and, a base homeserver URL.
    ///
    /// This creates a QR code which conforms to
    /// {@link https://github.com/matrix-org/matrix-spec-proposals/pull/4388 MSC4388} of the data
    /// format for QR login.
    #[wasm_bindgen(js_name = "newMsc4388")]
    pub fn new_msc4388(
        public_key: Curve25519PublicKey,
        rendezvous_id: String,
        base_url: &str,
        intent: QrCodeIntent,
    ) -> Result<QrCodeData, JsError> {
        let public_key = public_key.inner;
        let intent = intent.into();
        let base_url = Url::parse(base_url)?;

        let inner = qr_login::QrCodeData::new_msc4388(public_key, rendezvous_id, base_url, intent);

        Ok(QrCodeData { inner })
    }

    /// Attempt to decode a slice of bytes into a {@link QrCodeData} object.
    ///
    /// The slice of bytes would generally be returned by a QR code decoder.
    #[wasm_bindgen(js_name = "fromBytes")]
    pub fn from_bytes(bytes: &[u8]) -> Result<QrCodeData, JsError> {
        Ok(Self { inner: qr_login::QrCodeData::from_bytes(bytes)? })
    }

    /// Encode the {@link QrCodeData} into a list of bytes.
    ///
    /// The list of bytes can be used by a QR code generator to create an image
    /// containing a QR code.
    #[wasm_bindgen(js_name = "toBytes")]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes()
    }

    /// Attempt to decode a base64 encoded string into a {@link QrCodeData}
    /// object.
    #[wasm_bindgen(js_name = "fromBase64")]
    pub fn from_base64(data: &str) -> Result<QrCodeData, JsError> {
        Ok(Self { inner: qr_login::QrCodeData::from_base64(data)? })
    }

    /// Encode the {@link QrCodeData} into a string using base64.
    ///
    /// This format can be used for debugging purposes and the
    /// [`QrcodeData::from_base64()`] method can be used to parse the string
    /// again.
    #[wasm_bindgen(js_name = "toBase64")]
    pub fn to_base64(&self) -> String {
        self.inner.to_base64()
    }

    /// Get the Curve25519 public key embedded in the {@link QrCodeData}.
    ///
    /// This Curve25519 public key should be used to establish an
    /// [HPKE](https://www.rfc-editor.org/rfc/rfc9180.html)
    /// (Hybrid Public Key Encryption) channel with the other device.
    #[wasm_bindgen(getter, js_name = "publicKey")]
    pub fn public_key(&self) -> Curve25519PublicKey {
        self.inner.public_key().into()
    }

    /// Get the URL of the rendezvous server which will be used to exchange
    /// messages between the two devices.
    #[wasm_bindgen(getter, js_name = "rendezvousUrl")]
    pub fn rendezvous_url(&self) -> Option<String> {
        match self.inner.intent_data() {
            qr_login::QrCodeIntentData::Msc4108 { rendezvous_url, .. } => {
                Some(rendezvous_url.to_string())
            }
            qr_login::QrCodeIntentData::Msc4388 { .. } => None,
        }
    }

    /// Get the server name of the homeserver which the new device will be
    /// logged in to.
    ///
    /// This will be only available if the existing device has generated the QR
    /// code and the new device is the one scanning the QR code.
    #[wasm_bindgen(getter, js_name = "serverName")]
    pub fn server_name(&self) -> Option<String> {
        match self.inner.intent_data() {
            qr_login::QrCodeIntentData::Msc4108 { data, .. } => match data {
                qr_login::Msc4108IntentData::Login => None,
                qr_login::Msc4108IntentData::Reciprocate { server_name } => {
                    Some(server_name.to_owned())
                }
            },
            qr_login::QrCodeIntentData::Msc4388 { .. } => None,
        }
    }

    /// Get the mode of this {@link QrCodeData} instance.
    #[wasm_bindgen(getter)]
    pub fn mode(&self) -> QrCodeIntent {
        self.inner.intent().into()
    }

    /// Get the intent-specific data embedded in the {@link QrCodeData}.
    #[wasm_bindgen(getter, js_name = "intentData")]
    pub fn intent_data(&self) -> QrCodeIntentData {
        self.inner.intent_data().into()
    }
}
