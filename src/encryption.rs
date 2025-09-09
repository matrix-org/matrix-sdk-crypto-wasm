//! Encryption types & siblings.

use std::time::Duration;

use matrix_sdk_common::deserialized_responses::ShieldState as RustShieldState;
pub use matrix_sdk_common::deserialized_responses::ShieldStateCode;
use wasm_bindgen::prelude::*;

use crate::events;

/// Settings for an encrypted room.
///
/// This determines the algorithm and rotation periods of a group
/// session.
#[wasm_bindgen(getter_with_clone)]
#[derive(Debug, Clone)]
pub struct EncryptionSettings {
    /// The encryption algorithm that should be used in the room.
    pub algorithm: EncryptionAlgorithm,

    /// Whether state event encryption is enabled.
    #[wasm_bindgen(js_name = "encryptStateEvents")]
    pub encrypt_state_events: bool,

    /// How long the session should be used before changing it,
    /// expressed in microseconds.
    #[wasm_bindgen(js_name = "rotationPeriod")]
    pub rotation_period: u64,

    /// How many messages should be sent before changing the session.
    #[wasm_bindgen(js_name = "rotationPeriodMessages")]
    pub rotation_period_messages: u64,

    /// The history visibility of the room when the session was
    /// created.
    #[wasm_bindgen(js_name = "historyVisibility")]
    pub history_visibility: events::HistoryVisibility,

    /// Should untrusted devices receive the room key, or should they be
    /// excluded from the conversation.
    #[wasm_bindgen(js_name = "sharingStrategy")]
    pub sharing_strategy: CollectStrategy,
}

impl Default for EncryptionSettings {
    fn default() -> Self {
        let default = matrix_sdk_crypto::olm::EncryptionSettings::default();

        Self {
            algorithm: default.algorithm.into(),
            encrypt_state_events: default.encrypt_state_events,
            rotation_period: default.rotation_period.as_micros().try_into().unwrap(),
            rotation_period_messages: default.rotation_period_msgs,
            history_visibility: default.history_visibility.into(),
            sharing_strategy: default.sharing_strategy.into(),
        }
    }
}

#[wasm_bindgen]
impl EncryptionSettings {
    /// Create a new `EncryptionSettings` with default values.
    #[wasm_bindgen(constructor)]
    pub fn new() -> EncryptionSettings {
        Self::default()
    }
}

impl From<&EncryptionSettings> for matrix_sdk_crypto::olm::EncryptionSettings {
    fn from(value: &EncryptionSettings) -> Self {
        let algorithm = value.algorithm.clone().into();

        Self {
            algorithm,
            encrypt_state_events: value.encrypt_state_events,
            rotation_period: Duration::from_micros(value.rotation_period),
            rotation_period_msgs: value.rotation_period_messages,
            history_visibility: value.history_visibility.clone().into(),
            sharing_strategy: value.sharing_strategy.clone().into(),
        }
    }
}

/// An encryption algorithm to be used to encrypt messages sent to a
/// room.
#[wasm_bindgen]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncryptionAlgorithm {
    /// Olm version 1 using Curve25519, AES-256, and SHA-256.
    OlmV1Curve25519AesSha2,

    /// Megolm version 1 using AES-256 and SHA-256.
    MegolmV1AesSha2,

    /// Unsupported algorithm.
    ///
    /// Applications should ignore this value if it is received, and should
    /// never set it.
    Unknown,
}

impl From<EncryptionAlgorithm> for matrix_sdk_crypto::types::EventEncryptionAlgorithm {
    fn from(value: EncryptionAlgorithm) -> Self {
        use EncryptionAlgorithm::*;

        match value {
            OlmV1Curve25519AesSha2 => Self::OlmV1Curve25519AesSha2,
            MegolmV1AesSha2 => Self::MegolmV1AesSha2,
            _ => unreachable!("Unknown variant"),
        }
    }
}

impl From<matrix_sdk_crypto::types::EventEncryptionAlgorithm> for EncryptionAlgorithm {
    fn from(value: matrix_sdk_crypto::types::EventEncryptionAlgorithm) -> Self {
        use matrix_sdk_crypto::types::EventEncryptionAlgorithm::*;

        match value {
            OlmV1Curve25519AesSha2 => Self::OlmV1Curve25519AesSha2,
            MegolmV1AesSha2 => Self::MegolmV1AesSha2,
            _ => Self::Unknown,
        }
    }
}

/// Strategy to collect the devices that should receive room keys for the
/// current discussion.
#[wasm_bindgen()]
#[derive(Debug, Clone, PartialEq)]
pub struct CollectStrategy {
    inner: matrix_sdk_crypto::CollectStrategy,
}

#[wasm_bindgen]
impl CollectStrategy {
    /// Tests for equality between two [`CollectStrategy`]s.
    #[wasm_bindgen]
    pub fn eq(&self, other: &CollectStrategy) -> bool {
        self == other
    }
}

impl From<CollectStrategy> for matrix_sdk_crypto::CollectStrategy {
    fn from(value: CollectStrategy) -> Self {
        value.inner
    }
}

impl From<matrix_sdk_crypto::CollectStrategy> for CollectStrategy {
    fn from(value: matrix_sdk_crypto::CollectStrategy) -> Self {
        Self { inner: value }
    }
}

#[wasm_bindgen]
impl CollectStrategy {
    /// Device based sharing strategy.
    ///
    /// @deprecated: use one of {@link allDevices}, {@link
    /// errorOnUnverifiedUserProblem} or {@link onlyTrustedDevices}.
    #[wasm_bindgen(js_name = "deviceBasedStrategy")]
    pub fn device_based_strategy(
        only_allow_trusted_devices: bool,
        error_on_verified_user_problem: bool,
    ) -> CollectStrategy {
        if only_allow_trusted_devices {
            Self::only_trusted_devices()
        } else if error_on_verified_user_problem {
            Self::error_on_verified_user_problem()
        } else {
            Self::all_devices()
        }
    }

    /// Share with all (unblacklisted) devices.
    #[wasm_bindgen(js_name = "allDevices")]
    pub fn all_devices() -> CollectStrategy {
        Self { inner: matrix_sdk_crypto::CollectStrategy::AllDevices }
    }

    /// Share with all devices, except that errors for *verified* users cause
    /// sharing to fail with an error.
    ///
    /// In this strategy, if a verified user has an unsigned device, or
    /// a verified user has replaced their identity, key
    /// sharing will fail with an error.
    ///
    /// Otherwise, keys are shared with unsigned devices as normal.
    ///
    /// Once the problematic devices are blacklisted or whitelisted the
    /// caller can try sharing a second time.
    #[wasm_bindgen(js_name = "errorOnUnverifiedUserProblem")]
    pub fn error_on_verified_user_problem() -> CollectStrategy {
        Self { inner: matrix_sdk_crypto::CollectStrategy::ErrorOnVerifiedUserProblem }
    }

    /// Share based on identity. Only distribute to devices signed by their
    /// owner. If a user has no published identity he will not receive
    /// any room keys.
    #[wasm_bindgen(js_name = "identityBasedStrategy")]
    pub fn identity_based_strategy() -> CollectStrategy {
        Self { inner: matrix_sdk_crypto::CollectStrategy::IdentityBasedStrategy }
    }

    /// Only share keys with devices that we "trust". A device is trusted if any
    /// of the following is true:
    ///     - It was manually marked as trusted.
    ///     - It was marked as verified via interactive verification.
    ///     - It is signed by its owner identity, and this identity has been
    ///       trusted via interactive verification.
    ///     - It is the current own device of the user.
    #[wasm_bindgen(js_name = "onlyTrustedDevices")]
    pub fn only_trusted_devices() -> CollectStrategy {
        Self { inner: matrix_sdk_crypto::CollectStrategy::OnlyTrustedDevices }
    }
}

/// The trust level required to decrypt an event
#[wasm_bindgen]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustRequirement {
    /// Decrypt events from everyone regardless of trust
    Untrusted,
    /// Only decrypt events from cross-signed or legacy devices
    CrossSignedOrLegacy,
    /// Only decrypt events from cross-signed devices
    CrossSigned,
}

impl From<TrustRequirement> for matrix_sdk_crypto::TrustRequirement {
    fn from(value: TrustRequirement) -> Self {
        match value {
            TrustRequirement::Untrusted => Self::Untrusted,
            TrustRequirement::CrossSignedOrLegacy => Self::CrossSignedOrLegacy,
            TrustRequirement::CrossSigned => Self::CrossSigned,
        }
    }
}

/// Settings for decrypting messages
#[wasm_bindgen(getter_with_clone)]
#[derive(Debug, Clone)]
pub struct DecryptionSettings {
    /// The trust level required to decrypt the event
    pub sender_device_trust_requirement: TrustRequirement,
}

#[wasm_bindgen]
impl DecryptionSettings {
    /// Create a new `DecryptionSettings` with the given trust requirement.
    #[wasm_bindgen(constructor)]
    pub fn new(sender_device_trust_requirement: TrustRequirement) -> DecryptionSettings {
        Self { sender_device_trust_requirement }
    }
}

impl From<&DecryptionSettings> for matrix_sdk_crypto::DecryptionSettings {
    fn from(value: &DecryptionSettings) -> Self {
        Self {
            sender_device_trust_requirement: value.sender_device_trust_requirement.clone().into(),
        }
    }
}

/// Take a look at [`matrix_sdk_common::deserialized_responses::ShieldState`]
/// for more info.
#[wasm_bindgen]
#[derive(Debug, Clone, Copy)]
pub enum ShieldColor {
    /// Important warning
    Red,
    /// Low warning
    Grey,
    /// No warning
    None,
}

/// Take a look at [`matrix_sdk_common::deserialized_responses::ShieldState`]
/// for more info.
#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct ShieldState {
    /// The shield color
    pub color: ShieldColor,
    /// A machine-readable representation of the authenticity for a
    /// `ShieldState`.
    pub code: Option<ShieldStateCode>,
    message: Option<String>,
}

#[wasm_bindgen]
impl ShieldState {
    /// Error message that can be displayed as a tooltip
    #[wasm_bindgen(getter)]
    pub fn message(&self) -> Option<String> {
        self.message.clone()
    }
}

impl From<RustShieldState> for ShieldState {
    fn from(value: RustShieldState) -> Self {
        match value {
            RustShieldState::Red { message, code } => Self {
                color: ShieldColor::Red,
                code: Some(code),
                message: Some(message.to_owned()),
            },
            RustShieldState::Grey { message, code } => Self {
                color: ShieldColor::Grey,
                code: Some(code),
                message: Some(message.to_owned()),
            },
            RustShieldState::None => Self { color: ShieldColor::None, code: None, message: None },
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use wasm_bindgen_test::wasm_bindgen_test;
    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_node_experimental);

    use super::EncryptionAlgorithm;

    #[wasm_bindgen_test]
    fn test_convert_encryption_algorithm_to_js() {
        assert!(
            EncryptionAlgorithm::from(
                matrix_sdk_crypto::types::EventEncryptionAlgorithm::OlmV1Curve25519AesSha2
            ) == EncryptionAlgorithm::OlmV1Curve25519AesSha2
        );
        assert!(
            EncryptionAlgorithm::from(
                matrix_sdk_crypto::types::EventEncryptionAlgorithm::MegolmV1AesSha2
            ) == EncryptionAlgorithm::MegolmV1AesSha2
        );
        assert!(
            EncryptionAlgorithm::from(matrix_sdk_crypto::types::EventEncryptionAlgorithm::from(
                "unknown"
            )) == EncryptionAlgorithm::Unknown
        );
    }
}
