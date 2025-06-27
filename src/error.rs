//! Errors related to room event decryption.

use js_sys::JsString;
use matrix_sdk_common::deserialized_responses::{VerificationLevel, WithheldCode};
use matrix_sdk_crypto::{vodozemac, MegolmError};
use tracing::warn;
use wasm_bindgen::prelude::wasm_bindgen;

/// Decryption error codes
#[wasm_bindgen]
#[derive(Debug, Clone, Copy)]
pub enum DecryptionErrorCode {
    /// The room key is not known
    MissingRoomKey,
    /// The room key is known but ratcheted
    UnknownMessageIndex,
    /// Decryption failed because of a mismatch between the identity keys of the
    /// device we received the room key from and the identity keys recorded in
    /// the plaintext of the room key to-device message.
    MismatchedIdentityKeys,
    /// We weren't able to link the message back to any known device.
    UnknownSenderDevice,
    /// The sender device is not cross-signed.
    UnsignedSenderDevice,
    /// The sender's identity is unverified, but was previously verified.
    SenderIdentityVerificationViolation,
    /// Other failure.
    UnableToDecrypt,
}

/// Js Decryption error with code.
#[derive(Debug)]
#[wasm_bindgen(getter_with_clone)]
pub struct MegolmDecryptionError {
    /// Description code for the error. See `DecryptionErrorCode`
    #[wasm_bindgen(readonly)]
    pub code: DecryptionErrorCode,
    /// detailed description
    #[wasm_bindgen(readonly)]
    pub description: JsString,
    /// Withheld code if any. Only for `UnknownMessageIndex` error code
    #[wasm_bindgen(readonly)]
    pub maybe_withheld: Option<JsString>,
}

impl MegolmDecryptionError {
    /// Creates generic error with description
    pub fn unable_to_decrypt(desc: String) -> Self {
        Self {
            code: DecryptionErrorCode::UnableToDecrypt,
            description: desc.into(),
            maybe_withheld: None,
        }
    }
}

impl From<MegolmError> for MegolmDecryptionError {
    fn from(value: MegolmError) -> Self {
        let decryption_error = |code: DecryptionErrorCode,
                                maybe_withheld: Option<&WithheldCode>|
         -> MegolmDecryptionError {
            let description = value.to_string().into();
            let maybe_withheld = maybe_withheld.map(|code| code.to_string().to_owned().into());
            MegolmDecryptionError { code, description, maybe_withheld }
        };

        match &value {
            MegolmError::MissingRoomKey(withheld_code) => {
                decryption_error(DecryptionErrorCode::MissingRoomKey, withheld_code.as_ref())
            }
            MegolmError::Decryption(vodozemac::megolm::DecryptionError::UnknownMessageIndex(
                ..,
            )) => decryption_error(DecryptionErrorCode::UnknownMessageIndex, None),
            MegolmError::MismatchedIdentityKeys { .. } => {
                decryption_error(DecryptionErrorCode::UnknownMessageIndex, None)
            }
            MegolmError::SenderIdentityNotTrusted(vl) => match vl {
                VerificationLevel::VerificationViolation => {
                    decryption_error(DecryptionErrorCode::SenderIdentityVerificationViolation, None)
                }
                VerificationLevel::UnsignedDevice => {
                    decryption_error(DecryptionErrorCode::UnsignedSenderDevice, None)
                }
                VerificationLevel::None(..) => {
                    decryption_error(DecryptionErrorCode::UnknownSenderDevice, None)
                }
                VerificationLevel::UnverifiedIdentity => {
                    // We do not expect to find this in a MegolmError, since even at the strictest
                    // `TrustRequirement` level, we are happy to accept events from users whose
                    // identities we have not verified. We spit out a warning and then treat
                    // it as a generic UTD.
                    warn!("Unexpected verification level in megolm decryption error {}", value);
                    decryption_error(DecryptionErrorCode::UnableToDecrypt, None)
                }
            },
            _ => decryption_error(DecryptionErrorCode::UnableToDecrypt, None),
        }
    }
}
