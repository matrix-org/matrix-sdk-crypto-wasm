//! This module implements [HPKE](https://www.rfc-editor.org/rfc/rfc9180.html).
//!
//! Please take a look at the vodozemac documentation of this module for more
//! info.

#![allow(missing_debug_implementations)]
use std::sync::{Arc, Mutex};

use matrix_sdk_crypto::vodozemac::hpke;
use wasm_bindgen::prelude::*;

use super::Curve25519PublicKey;

fn used_up_error() -> JsError {
    JsError::new("The HPKE channel was already established and used up.")
}

/// The result of an recipient HPKE channel establishment.
#[wasm_bindgen(getter_with_clone)]
pub struct HpkeRecipientCreationResult {
    /// The established HPKE channel.
    pub channel: UnidirectionalRecipientChannel,
    /// The plaintext of the initial message.
    pub message: String,
}

/// The result of an inbound HPKE channel establishment.
#[wasm_bindgen(getter_with_clone)]
pub struct HpkeSenderCreationResult {
    /// The established HPKE channel.
    pub channel: UnidirectionalSenderChannel,
    /// The initial encrypted message.
    pub message: String,
}

/// The result of an outbound HPKE channel establishment.
#[wasm_bindgen(getter_with_clone)]
pub struct BidirectionalCreationResult {
    /// The fully established HPKE channel.
    pub channel: EstablishedHpkeChannel,
    /// The initial response.
    #[wasm_bindgen(js_name = "initialResponse")]
    pub initial_response: String,
}

/// An unestablished HPKE session.
#[wasm_bindgen]
pub struct HpkeRecipientChannel {
    inner: Option<hpke::HpkeRecipientChannel>,
    public_key: Curve25519PublicKey,
}

#[wasm_bindgen]
impl HpkeRecipientChannel {
    /// Create a new, random, unestablished HPKE session.
    ///
    /// This method will use the
    /// [`MATRIX_QR_CODE_LOGIN`](https://github.com/matrix-org/matrix-spec-proposals/pull/4108)
    /// info for domain separation when creating the session.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        let inner = hpke::HpkeRecipientChannel::new();
        let public_key = inner.public_key().into();

        Self { inner: Some(inner), public_key }
    }

    /// Get our { @link Curve25519PublicKey }.
    ///
    /// This public key needs to be sent to the other side to be able to
    /// establish an HPKE channel.
    #[wasm_bindgen(getter, js_name = "publicKey")]
    pub fn public_key(&self) -> Curve25519PublicKey {
        self.public_key.clone()
    }

    /// Create a { @link UnidirectionalRecipientChannel } from an initial
    /// message encrypted by the other side.
    #[wasm_bindgen(js_name = "establishChannel")]
    pub fn establish_channel(
        &mut self,
        initial_message: &str,
        aad: &str,
    ) -> Result<HpkeRecipientCreationResult, JsError> {
        let message = hpke::InitialMessage::decode(&initial_message)?;
        let result = self
            .inner
            .take()
            .ok_or_else(used_up_error)?
            .establish_channel(&message, aad.as_bytes())?;

        let message = String::from_utf8_lossy(&result.message).to_string();

        Ok(HpkeRecipientCreationResult { message, channel: result.channel.into() })
    }
}

#[wasm_bindgen]
#[derive(Clone)]
pub struct UnidirectionalRecipientChannel {
    inner: Arc<Mutex<Option<hpke::UnidirectionalRecipientChannel>>>,
}

#[wasm_bindgen]
impl UnidirectionalRecipientChannel {
    #[wasm_bindgen(js_name = "establishBidirectionalChannel")]
    pub fn establish_bidirectional_channel(
        &mut self,
        initial_response: &str,
        aad: &str,
    ) -> Result<BidirectionalCreationResult, JsError> {
        let hpke::BidirectionalCreationResult { channel, message } = self
            .inner
            .lock()
            .unwrap()
            .take()
            .ok_or_else(used_up_error)?
            .establish_bidirectional_channel(&initial_response.as_bytes(), aad.as_bytes());

        Ok(BidirectionalCreationResult {
            channel: channel.into(),
            initial_response: message.encode(),
        })
    }
}

/// An unestablished HPKE channel.
#[wasm_bindgen]
pub struct HpkeSenderChannel {
    inner: Option<hpke::HpkeSenderChannel>,
}

#[wasm_bindgen]
impl HpkeSenderChannel {
    /// Create a new, random, unestablished HPKE session.
    ///
    /// This method will use the
    /// [`MATRIX_QR_CODE_LOGIN`](https://github.com/matrix-org/matrix-spec-proposals/pull/4108)
    /// info for domain separation when creating the session.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        let inner = hpke::HpkeSenderChannel::new();

        Self { inner: Some(inner) }
    }

    /// Create a { @link UnidirectionalRecipientChannel } from an initial
    /// message encrypted by the other side.
    #[wasm_bindgen(js_name = "establishChannel")]
    pub fn establish_channel(
        &mut self,
        their_public_key: Curve25519PublicKey,
        initial_message: &str,
        aad: &str,
    ) -> Result<HpkeSenderCreationResult, JsError> {
        let hpke::SenderCreationResult { channel, message } = self
            .inner
            .take()
            .ok_or_else(used_up_error)?
            .establish_channel(their_public_key.inner, &initial_message.as_bytes(), aad.as_bytes());

        Ok(HpkeSenderCreationResult { message: message.encode(), channel: channel.into() })
    }
}

#[wasm_bindgen]
#[derive(Clone)]
pub struct UnidirectionalSenderChannel {
    inner: Arc<Mutex<Option<hpke::UnidirectionalSenderChannel>>>,
}

#[wasm_bindgen]
impl UnidirectionalSenderChannel {
    #[wasm_bindgen(js_name = "establishBidirectionalChannel")]
    pub fn establish_bidirectional_channel(
        &mut self,
        initial_response: &str,
        aad: &str,
    ) -> Result<BidirectionalCreationResult, JsError> {
        let initial_response = hpke::InitialResponse::decode(initial_response)?;

        let hpke::BidirectionalCreationResult { channel, message } = self
            .inner
            .lock()
            .unwrap()
            .take()
            .ok_or_else(used_up_error)?
            .establish_bidirectional_channel(&initial_response, aad.as_bytes())?;

        let message = String::from_utf8(message)?;

        Ok(BidirectionalCreationResult { channel: channel.into(), initial_response: message })
    }
}

/// A fully established HPKE channel.
///
/// This channel can be used to seal and open messages between the two
/// sides of the channel.
#[derive(Clone)]
#[wasm_bindgen]
pub struct EstablishedHpkeChannel {
    inner: Arc<Mutex<hpke::EstablishedHpkeChannel>>,
}

#[wasm_bindgen]
impl EstablishedHpkeChannel {
    /// Get our [`Curve25519PublicKey`].
    ///
    /// This public key needs to be sent to the other side so that it can
    /// complete the HPKE channel establishment.
    #[wasm_bindgen(getter, js_name = "publicKey")]
    pub fn public_key(&self) -> Curve25519PublicKey {
        self.inner.lock().unwrap().public_key().into()
    }

    /// Encrypt the given plaintext using this HPKE channel.
    pub fn seal(&mut self, message: &str, aad: &str) -> String {
        self.inner.lock().unwrap().seal(message.as_bytes(), aad.as_bytes()).encode()
    }

    /// Decrypt the given message using this HPKE channel.
    pub fn open(&mut self, message: &str, aad: &str) -> Result<String, JsError> {
        let message = hpke::Message::decode(message)?;
        let result = self.inner.lock().unwrap().open(&message, aad.as_bytes())?;

        Ok(String::from_utf8_lossy(&result).to_string())
    }

    /// Get the [`CheckCode`] which uniquely identifies this { @link
    /// EstablishedHpkeChannel }.
    ///
    /// This check code can be used to verify and confirm that both sides of the
    /// session are indeed using the same shared secret.
    #[wasm_bindgen(getter, js_name = "checkCode")]
    pub fn check_code(&self) -> HpkeCheckCode {
        self.inner.lock().unwrap().check_code().into()
    }
}

/// A check code that can be used to confirm that two { @link
/// EstablishedHpkeChannel } objects share the same secret. This is supposed to
/// be shared out-of-band to protect against active Man-in-the-middle (MITM)
/// attacks.
///
/// Since the initiator device can always tell whether a MITM attack is in
/// progress after channel establishment, this code technically carries only a
/// single bit of information, representing whether the initiator has determined
/// that the channel is "secure" or "not secure".
///
/// However, given this will need to be interactively confirmed by the user,
/// there is risk that the user would confirm the dialogue without paying
/// attention to its content. By expanding this single bit into a deterministic
/// two-digit check code, the user is forced to pay more attention by having to
/// enter it instead of just clicking through a dialogue.
#[derive(Clone)]
#[wasm_bindgen]
pub struct HpkeCheckCode {
    inner: matrix_sdk_crypto::vodozemac::hpke::CheckCode,
}

#[wasm_bindgen]
impl HpkeCheckCode {
    /// Convert the check code to an array of two bytes.
    ///
    /// The bytes can be converted to a more user-friendly representation. The
    /// [`CheckCode::to_digit`] converts the bytes to a two-digit number.
    pub fn as_bytes(&self) -> Vec<u8> {
        self.inner.as_bytes().to_vec()
    }

    /// Convert the check code to two base-10 numbers.
    ///
    /// The number should be displayed with a leading 0 in case the first digit
    /// is a 0.
    pub fn to_digit(&self) -> u8 {
        self.inner.to_digit(hpke::DigitMode::NoLeadingZero)
    }
}

impl From<&hpke::CheckCode> for HpkeCheckCode {
    fn from(value: &matrix_sdk_crypto::vodozemac::hpke::CheckCode) -> Self {
        Self { inner: value.clone() }
    }
}

impl From<hpke::EstablishedHpkeChannel> for EstablishedHpkeChannel {
    fn from(value: hpke::EstablishedHpkeChannel) -> Self {
        Self { inner: Mutex::new(value).into() }
    }
}

impl From<hpke::UnidirectionalRecipientChannel> for UnidirectionalRecipientChannel {
    fn from(value: hpke::UnidirectionalRecipientChannel) -> Self {
        Self { inner: Mutex::new(Some(value)).into() }
    }
}

impl From<hpke::UnidirectionalSenderChannel> for UnidirectionalSenderChannel {
    fn from(value: hpke::UnidirectionalSenderChannel) -> Self {
        Self { inner: Mutex::new(Some(value)).into() }
    }
}
