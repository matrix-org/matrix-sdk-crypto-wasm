//! Wrap the JavaScript X.509 signer into an instance of RawX509Signer

use std::{
    future::{ready, Future},
    pin::Pin,
    sync::Arc,
    time::Duration,
};

use js_sys::{Promise, Uint8Array};
use matrix_sdk_crypto::{
    x509::{
        RawX509Signature, RawX509Signer, ValidityError, X509SignatureScheme,
        X509SignatureSigningError,
    },
    OlmMachineBuilder, SignatureError,
};
use serde::Deserialize;
use wasm_bindgen::JsValue;
use wasm_bindgen_futures::JsFuture;

pub fn wrap_x509_signer(
    raw_x509_signer: X509SignFn,
    raw_x509_validity: X509ValidityFn,
    builder: OlmMachineBuilder,
) -> OlmMachineBuilder {
    if cfg!(not(target_family = "wasm")) {
        panic!(
            "Providing a JavaScript X.509 signing function is \
                not supported outside the WASM target."
        );
    }

    let signer =
        Arc::new(JsRawX509Signer { signer_fn: raw_x509_signer, validity_fn: raw_x509_validity });

    builder.with_x509_signer(Some(signer))
}

#[derive(Debug, thiserror::Error)]
enum JsSignerError {
    #[error("The supplied signing function failed: {0}")]
    SuppliedFunctionFailed(String),

    #[error("The supplied signing function returned an invalid response: {0}")]
    InvalidResponse(String),

    #[error("The supplied signing function returned an unsupported signature scheme: {0}")]
    UnsupportedSignatureScheme(String),
}

/// The type of the user-provided JavaScript signer function for signing items
/// via X.509. The returned JsValue must be an object like this:
///
/// ```
/// {
///     signature_bytes: Uint8Array,
///     certificate_chain: string,
///     signature_scheme: "RsaPssSha512"
/// }
/// ```
///
/// Note that `signature_scheme` must be "RsaPssSha512" since that is the only
/// supported signature scheme.
pub type X509SignFn = js_sys::Function<fn(Uint8Array) -> Promise<JsValue>>;

#[derive(Deserialize)]
struct X509Signature {
    /// The raw bytes of the signature.
    pub signature_bytes: Vec<u8>,

    /// The PEM-encoded certificate chain, starting with the device's own
    /// certificate, followed by intermediate certificates.
    pub certificate_chain: String,

    /// The algorithm that the signer used to construct the signature. The only
    /// valid value is "RsaPssSha512".
    pub signature_scheme: String,
}

/// The type of the user-provided JavaScript validity function that should
/// return the certificate's validity period in milliseconds since the Unix
/// epoch.
///
/// The returned value must be a number representing the number of milliseconds
/// since the Unix epoch.
pub type X509ValidityFn = js_sys::Function<fn() -> JsValue>;

#[derive(Debug)]
struct JsRawX509Signer {
    signer_fn: X509SignFn,
    validity_fn: X509ValidityFn,
}

#[cfg(not(target_family = "wasm"))]
impl RawX509Signer for JsRawX509Signer {
    fn sign(
        &self,
        _message: Vec<u8>,
    ) -> Pin<Box<dyn Future<Output = Result<RawX509Signature, SignatureError>> + Send>> {
        panic!("Can't use RawX509Signer outside of a WASM target");
    }

    /// Return the "not after" time for the certificate's validity
    /// period.
    fn validity_not_after(&self) -> Result<Duration, ValidityError> {
        panic!("Can't use RawX509Signer outside of a WASM target");
    }
}

#[cfg(target_family = "wasm")]
impl RawX509Signer for JsRawX509Signer {
    fn sign(
        &self,
        message: Vec<u8>,
    ) -> Pin<Box<dyn Future<Output = Result<RawX509Signature, SignatureError>>>> {
        // We break out the implementation into a not WASM-only function to aid
        // development and testing
        self.do_sign(message)
    }

    /// Return the "not after" time for the certificate's validity
    /// period.
    fn validity_not_after(&self) -> Result<Duration, ValidityError> {
        // We break out the implementation into a not WASM-only function to aid
        // development and testing
        self.do_validity_not_after()
    }
}

impl From<JsSignerError> for SignatureError {
    fn from(value: JsSignerError) -> Self {
        SignatureError::X509SigningError(X509SignatureSigningError::Custom(Box::new(value)))
    }
}

impl JsRawX509Signer {
    fn do_sign(
        &self,
        message: Vec<u8>,
    ) -> Pin<Box<dyn Future<Output = Result<RawX509Signature, SignatureError>>>> {
        let signature_promise_result =
            self.signer_fn.call(&JsValue::NULL, (&Uint8Array::new_from_slice(&message),));

        let signature_promise = match signature_promise_result {
            Ok(p) => p,
            Err(e) => {
                return Box::pin(ready(Err(JsSignerError::SuppliedFunctionFailed(format!(
                    "{e:?}"
                ))
                .into())));
            }
        };

        Box::pin(await_signing_result(JsFuture::from(signature_promise)))
    }

    /// Return the "not after" time for the certificate's validity
    /// period.
    fn do_validity_not_after(&self) -> Result<Duration, ValidityError> {
        let res = self.validity_fn.call(&JsValue::NULL, ()).map_err(|_| ValidityError)?;

        if let Some(millis) = res.as_f64() {
            // Casting from a float to an integer will round the float towards
            // zero
            let millis = millis as u64;
            Ok(Duration::from_millis(millis))
        } else {
            Err(ValidityError)
        }
    }
}

async fn await_signing_result(
    signature_future: JsFuture,
) -> Result<RawX509Signature, SignatureError> {
    let signature: JsValue = signature_future
        .await
        .map_err(|e| JsSignerError::SuppliedFunctionFailed(format!("{e:?}")))?;

    let signature: X509Signature = serde_wasm_bindgen::from_value(signature)
        .map_err(|e| JsSignerError::InvalidResponse(format!("{e:?}")))?;

    let signature_scheme = match signature.signature_scheme.as_str() {
        "RsaPssSha512" => X509SignatureScheme::RsaPssSha512,
        ss => {
            return Err(JsSignerError::UnsupportedSignatureScheme(ss.to_owned()).into());
        }
    };

    Ok(RawX509Signature {
        signature_bytes: signature.signature_bytes,
        certificate_chain: signature.certificate_chain,
        signature_scheme,
    })
}
