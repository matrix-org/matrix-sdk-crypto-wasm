//! User identities.

use js_sys::{Array, Promise};
use wasm_bindgen::prelude::*;

use crate::{
    future::future_to_promise,
    identifiers, impl_from_to_inner, requests,
    verification::{self, VerificationRequest},
};

pub(crate) struct UserIdentity {
    inner: matrix_sdk_crypto::UserIdentity,
}

impl_from_to_inner!(matrix_sdk_crypto::UserIdentity => UserIdentity);

impl From<UserIdentity> for JsValue {
    fn from(user_identities: UserIdentity) -> Self {
        use matrix_sdk_crypto::UserIdentity::*;

        match user_identities.inner {
            Own(own) => JsValue::from(OwnUserIdentity::from(own)),
            Other(other) => JsValue::from(OtherUserIdentity::from(other)),
        }
    }
}

/// Struct representing a cross signing identity of a user.
///
/// This is the user identity of a user that is our own.
#[wasm_bindgen]
#[derive(Debug)]
pub struct OwnUserIdentity {
    inner: matrix_sdk_crypto::OwnUserIdentity,
}

impl_from_to_inner!(matrix_sdk_crypto::OwnUserIdentity => OwnUserIdentity);

#[wasm_bindgen]
impl OwnUserIdentity {
    /// Is this user identity verified?
    #[wasm_bindgen(js_name = "isVerified")]
    pub fn is_verified(&self) -> bool {
        self.inner.is_verified()
    }

    /// Mark our user identity as verified.
    ///
    /// This will mark the identity locally as verified and sign it with our own
    /// device.
    ///
    /// Returns a signature upload request that needs to be sent out.
    #[wasm_bindgen(unchecked_return_type = "Promise<SignatureUploadRequest>")]
    pub fn verify(&self) -> Promise {
        let me = self.inner.clone();

        future_to_promise(async move {
            Ok(requests::SignatureUploadRequest::try_from(&me.verify().await?)?)
        })
    }

    /// Send a verification request to our other devices.
    #[wasm_bindgen(
        js_name = "requestVerification",
        unchecked_return_type = "Promise<[VerificationRequest, OutgoingVerificationRequest]>"
    )]
    pub fn request_verification(
        &self,
        #[wasm_bindgen(unchecked_optional_param_type = "VerificationMethod[]")] methods: Option<
            Vec<verification::VerificationMethod>,
        >,
    ) -> Result<Promise, JsError> {
        let methods = methods.map(|methods| methods.iter().map(Into::into).collect());
        let me = self.inner.clone();

        Ok(future_to_promise(async move {
            let tuple = Array::new();
            let (verification_request, outgoing_verification_request) = match methods {
                Some(methods) => me.request_verification_with_methods(methods).await?,
                None => me.request_verification().await?,
            };

            tuple.set(0, verification::VerificationRequest::from(verification_request).into());
            tuple.set(
                1,
                verification::OutgoingVerificationRequest::from(outgoing_verification_request)
                    .try_into()?,
            );

            Ok(tuple)
        }))
    }

    /// Does our user identity trust our own device, i.e. have we signed our own
    /// device keys with our self-signing key?
    #[wasm_bindgen(js_name = "trustsOurOwnDevice", unchecked_return_type = "Promise<boolean>")]
    pub fn trusts_our_own_device(&self) -> Promise {
        let me = self.inner.clone();

        future_to_promise(async move { Ok(me.trusts_our_own_device().await?) })
    }

    /// Get the master key of the identity.
    #[wasm_bindgen(getter, js_name = "masterKey")]
    pub fn master_key(&self) -> Result<String, JsError> {
        let master_key = self.inner.master_key().as_ref();
        Ok(serde_json::to_string(master_key)?)
    }

    /// Get the self-signing key of the identity.
    #[wasm_bindgen(getter, js_name = "selfSigningKey")]
    pub fn self_signing_key(&self) -> Result<String, JsError> {
        let self_signing_key = self.inner.self_signing_key().as_ref();
        Ok(serde_json::to_string(self_signing_key)?)
    }

    /// Get the user-signing key of the identity. This is only present for our
    /// own user identity.
    #[wasm_bindgen(getter, js_name = "userSigningKey")]
    pub fn user_signing_key(&self) -> Result<String, JsError> {
        let user_signing_key = self.inner.user_signing_key().as_ref();
        Ok(serde_json::to_string(user_signing_key)?)
    }

    /// True if we verified our own identity at some point in the past.
    ///
    /// To reset this latch back to `false`, call {@link withdrawVerification}.
    #[wasm_bindgen(js_name = wasPreviouslyVerified)]
    pub fn was_previously_verified(&self) -> bool {
        self.inner.was_previously_verified()
    }

    /// Remove the requirement for this identity to be verified.
    ///
    /// If an identity was previously verified and is not any longer, it will be
    /// reported to the user. In order to remove this notice users have to
    /// verify again or to withdraw the verification requirement.
    #[wasm_bindgen(js_name = "withdrawVerification", unchecked_return_type = "Promise<void>")]
    pub fn withdraw_verification(&self) -> Promise {
        let me = self.inner.clone();

        future_to_promise(async move {
            let _ = &me.withdraw_verification().await?;
            Ok(JsValue::undefined())
        })
    }

    /// Was this identity verified since initial observation and is not anymore?
    ///
    /// Such a violation should be reported to the local user by the
    /// application, and resolved by
    ///
    /// - Verifying the new identity with {@link requestVerification}, or:
    /// - Withdrawing the verification requirement with {@link
    ///   withdrawVerification}.
    #[wasm_bindgen(js_name = "hasVerificationViolation")]
    pub fn has_verification_violation(&self) -> bool {
        self.inner.has_verification_violation()
    }
}

/// Struct representing a cross signing identity of a user.
///
/// This is the user identity of a user that isn't our own. Other users will
/// only contain a master key and a self signing key, meaning that only device
/// signatures can be checked with this identity.
///
/// This struct wraps a read-only version of the struct and allows verifications
/// to be requested to verify our own device with the user identity.
#[wasm_bindgen]
#[derive(Debug)]
pub struct OtherUserIdentity {
    inner: matrix_sdk_crypto::OtherUserIdentity,
}

impl_from_to_inner!(matrix_sdk_crypto::OtherUserIdentity => OtherUserIdentity);

#[wasm_bindgen]
impl OtherUserIdentity {
    /// Is this user identity verified?
    #[wasm_bindgen(js_name = "isVerified")]
    pub fn is_verified(&self) -> bool {
        self.inner.is_verified()
    }

    /// Manually verify this user.
    ///
    /// This method will attempt to sign the user identity using our private
    /// cross signing key.
    ///
    /// This method fails if we don't have the private part of our user-signing
    /// key.
    ///
    /// Returns a request that needs to be sent out for the user to be marked as
    /// verified.
    #[wasm_bindgen(unchecked_return_type = "Promise<SignatureUploadRequest>")]
    pub fn verify(&self) -> Promise {
        let me = self.inner.clone();

        future_to_promise(async move {
            Ok(requests::SignatureUploadRequest::try_from(&me.verify().await?)?)
        })
    }

    /// Create a `VerificationRequest` object after the verification
    /// request content has been sent out.
    #[wasm_bindgen(js_name = "requestVerification")]
    pub fn request_verification(
        &self,
        room_id: &identifiers::RoomId,
        request_event_id: &identifiers::EventId,
        #[wasm_bindgen(unchecked_optional_param_type = "VerificationMethod[]")] methods: Option<
            Vec<verification::VerificationMethod>,
        >,
    ) -> Result<VerificationRequest, JsError> {
        let me = self.inner.clone();
        let room_id = room_id.inner.clone();
        let request_event_id = request_event_id.inner.clone();
        let methods = methods.map(|methods| methods.iter().map(Into::into).collect());

        Ok(me.request_verification(room_id.as_ref(), request_event_id.as_ref(), methods).into())
    }

    /// Send a verification request to the given user.
    ///
    /// The returned content needs to be sent out into a DM room with the given
    /// user.
    ///
    /// After the content has been sent out a VerificationRequest can be started
    /// with the `request_verification` method.
    #[wasm_bindgen(js_name = "verificationRequestContent")]
    pub fn verification_request_content(
        &self,
        #[wasm_bindgen(unchecked_optional_param_type = "VerificationMethod[]")] methods: Option<
            Vec<verification::VerificationMethod>,
        >,
    ) -> Result<String, JsError> {
        let me = self.inner.clone();
        let methods = methods.map(|methods| methods.iter().map(Into::into).collect());

        Ok(serde_json::to_string(&me.verification_request_content(methods))?)
    }

    /// Get the master key of the identity.
    #[wasm_bindgen(getter, js_name = "masterKey")]
    pub fn master_key(&self) -> Result<String, JsError> {
        let master_key = self.inner.master_key().as_ref();
        Ok(serde_json::to_string(master_key)?)
    }

    /// Get the self-signing key of the identity.
    #[wasm_bindgen(getter, js_name = "selfSigningKey")]
    pub fn self_signing_key(&self) -> Result<String, JsError> {
        let self_signing_key = self.inner.self_signing_key().as_ref();
        Ok(serde_json::to_string(self_signing_key)?)
    }

    /// Pin the current identity (public part of the master signing key).
    #[wasm_bindgen(js_name = "pinCurrentMasterKey", unchecked_return_type = "Promise<void>")]
    pub fn pin_current_master_key(&self) -> Promise {
        let me = self.inner.clone();

        future_to_promise(async move {
            let _ = &me.pin_current_master_key().await?;
            Ok(JsValue::undefined())
        })
    }

    /// Has the identity changed in a way that requires approval from the user?
    ///
    /// A user identity needs approval if it changed after the crypto machine
    /// has already observed ("pinned") a different identity for that user,
    /// unless it is an explicitly verified identity (using for example
    /// interactive verification).
    ///
    /// This situation can be resolved by:
    ///
    /// - Verifying the new identity with {@link requestVerification}, or:
    /// - Updating the pin to the new identity with {@link pinCurrentMasterKey}.
    #[wasm_bindgen(js_name = "identityNeedsUserApproval")]
    pub fn identity_needs_user_approval(&self) -> bool {
        self.inner.identity_needs_user_approval()
    }

    /// True if we verified this identity (with any own identity, at any
    /// point).
    ///
    /// To set this latch back to false, call {@link withdrawVerification}.
    #[wasm_bindgen(js_name = "wasPreviouslyVerified")]
    pub fn was_previously_verified(&self) -> bool {
        self.inner.was_previously_verified()
    }

    /// Remove the requirement for this identity to be verified.
    ///
    /// If an identity was previously verified and is not anymore it will be
    /// reported to the user. In order to remove this notice users have to
    /// verify again or to withdraw the verification requirement.
    #[wasm_bindgen(js_name = "withdrawVerification", unchecked_return_type = "Promise<void>")]
    pub fn withdraw_verification(&self) -> Promise {
        let me = self.inner.clone();

        future_to_promise(async move {
            let _ = &me.withdraw_verification().await?;
            Ok(JsValue::undefined())
        })
    }

    /// Was this identity verified since initial observation and is not anymore?
    ///
    /// Such a violation should be reported to the local user by the
    /// application, and resolved by
    ///
    /// - Verifying the new identity with {@link requestVerification}, or:
    /// - Withdrawing the verification requirement with {@link
    ///   withdrawVerification}.
    #[wasm_bindgen(js_name = "hasVerificationViolation")]
    pub fn has_verification_violation(&self) -> bool {
        self.inner.has_verification_violation()
    }
}
