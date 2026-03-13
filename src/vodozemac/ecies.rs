//! This module implements [ECIES](https://en.wikipedia.org/wiki/Integrated_Encryption_Scheme), the
//! elliptic curve variant of the Integrated Encryption Scheme.
//!
//! Please take a look at the vodozemac documentation of this module for more
//! info.

#![allow(missing_debug_implementations)]
use std::sync::{Arc, Mutex};

use matrix_sdk_crypto::vodozemac::ecies;
use wasm_bindgen::prelude::*;

use super::Curve25519PublicKey;

/// The result of an inbound ECIES channel establishment.
#[wasm_bindgen(getter_with_clone)]
pub struct InboundCreationResult {
    /// The established ECIES channel.
    pub channel: EstablishedEcies,
    /// The plaintext of the initial message.
    pub message: String,
}

/// The result of an outbound ECIES channel establishment.
#[wasm_bindgen(getter_with_clone)]
pub struct OutboundCreationResult {
    /// The established ECIES channel.
    pub channel: EstablishedEcies,
    /// The initial encrypted message.
    pub initial_message: String,
}

/// An unestablished ECIES session.
#[wasm_bindgen]
pub struct Ecies {
    inner: Option<ecies::Ecies>,
    public_key: Curve25519PublicKey,
}

#[wasm_bindgen]
impl Ecies {
    /// Create a new, random, unestablished ECIES session.
    ///
    /// This method will use the
    /// [`MATRIX_QR_CODE_LOGIN`](https://github.com/matrix-org/matrix-spec-proposals/pull/4108)
    /// info for domain separation when creating the session.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        let inner = ecies::Ecies::new();
        let public_key = inner.public_key().into();

        Self { inner: Some(inner), public_key }
    }

    /// Get our [`Curve25519PublicKey`].
    ///
    /// This public key needs to be sent to the other side to be able to
    /// establish an ECIES channel.
    pub fn public_key(&self) -> Curve25519PublicKey {
        self.public_key.clone()
    }

    fn used_up_error() -> JsError {
        JsError::new("The ECIES channel was already established and used up.")
    }

    /// Create a [`EstablishedEcies`] from an initial message encrypted by the
    /// other side.
    pub fn establish_inbound_channel(
        &mut self,
        initial_message: &str,
    ) -> Result<InboundCreationResult, JsError> {
        let message = ecies::InitialMessage::decode(&initial_message)?;
        let result = self
            .inner
            .take()
            .ok_or_else(Self::used_up_error)?
            .establish_inbound_channel(&message)?;

        let message = String::from_utf8_lossy(&result.message).to_string();

        Ok(InboundCreationResult { message, channel: result.ecies.into() })
    }

    /// Create an [`EstablishedEcies`] session using the other side's Curve25519
    /// public key and an initial plaintext.
    ///
    /// After the channel has been established, we can encrypt messages to send
    /// to the other side. The other side uses the initial message to
    /// establishes the same channel on its side.
    pub fn establish_outbound_channel(
        &mut self,
        public_key: &Curve25519PublicKey,
        initial_message: &str,
    ) -> Result<OutboundCreationResult, JsError> {
        let result = self
            .inner
            .take()
            .ok_or_else(Self::used_up_error)?
            .establish_outbound_channel(public_key.inner, initial_message.as_bytes())?;

        Ok(OutboundCreationResult {
            initial_message: result.message.encode(),
            channel: result.ecies.into(),
        })
    }
}

/// An established ECIES session.
///
/// This session can be used to encrypt and decrypt messages between the two
/// sides of the channel.
#[derive(Clone)]
#[wasm_bindgen]
pub struct EstablishedEcies {
    inner: Arc<Mutex<ecies::EstablishedEcies>>,
}

#[wasm_bindgen]
impl EstablishedEcies {
    /// Get our [`Curve25519PublicKey`].
    ///
    /// This public key needs to be sent to the other side so that it can
    /// complete the ECIES channel establishment.
    pub fn public_key(&self) -> Curve25519PublicKey {
        self.inner.lock().unwrap().public_key().into()
    }

    /// Encrypt the given plaintext using this [`EstablishedEcies`] session.
    pub fn encrypt(&mut self, message: &str) -> String {
        self.inner.lock().unwrap().encrypt(message.as_bytes()).encode()
    }

    /// Decrypt the given message using this [`EstablishedEcies`] session.
    pub fn decrypt(&mut self, message: &str) -> Result<String, JsError> {
        let message = ecies::Message::decode(message)?;
        let result = self.inner.lock().unwrap().decrypt(&message)?;

        Ok(String::from_utf8_lossy(&result).to_string())
    }

    /// Get the [`CheckCode`] which uniquely identifies this
    /// [`EstablishedEcies`] session.
    ///
    /// This check code can be used to verify and confirm that both sides of the
    /// session are indeed using the same shared secret.
    pub fn check_code(&self) -> CheckCode {
        self.inner.lock().unwrap().check_code().into()
    }
}

/// A check code that can be used to confirm that two [`EstablishedEcies`]
/// objects share the same secret. This is supposed to be shared out-of-band to
/// protect against active Man-in-the-middle (MITM) attacks.
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
pub struct CheckCode {
    inner: matrix_sdk_crypto::vodozemac::ecies::CheckCode,
}

#[wasm_bindgen]
impl CheckCode {
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
        self.inner.to_digit(ecies::DigitMode::AllowLeadingZero)
    }
}

impl From<&ecies::CheckCode> for CheckCode {
    fn from(value: &matrix_sdk_crypto::vodozemac::ecies::CheckCode) -> Self {
        Self { inner: value.clone() }
    }
}

impl From<ecies::EstablishedEcies> for EstablishedEcies {
    fn from(value: ecies::EstablishedEcies) -> Self {
        Self { inner: Mutex::new(value).into() }
    }
}
