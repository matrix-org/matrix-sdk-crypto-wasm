use std::future::Future;

use js_sys::Promise;
use tracing::instrument::WithSubscriber;
use wasm_bindgen::{JsError, JsValue, UnwrapThrowExt};
use wasm_bindgen_futures::spawn_local;

/**
 * Convert a Rust [`Future`] which returns [`Result<T, JsError>`] into a
 * Javascript [`Promise`] which either resolves with an object of type `T`,
 * or rejects with an error of type [`Error`].
 *
 * Also applies [`WithSubscriber::with_current_subscriber`] to the future,
 * to ensure that the active tracing subscriber remains active while the
 * future is polled.
 *
 * [`Error`]: https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Error
 */
pub(crate) fn future_to_promise<F, T>(future: F) -> Promise
where
    F: Future<Output = Result<T, JsError>> + 'static,
    T: Into<JsValue>,
{
    future_to_promise_with_custom_error(future)
}

/**
 * Convert a Rust [`Future`] which returns [`Result<T, E>`] into a
 * Javascript [`Promise`] which either resolves with an object of type `T`,
 * or rejects with an error of type `E`.
 *
 * Also applies [`WithSubscriber::with_current_subscriber`] to the future,
 * to ensure that the active tracing subscriber remains active while the
 * future is polled.
 */
pub(crate) fn future_to_promise_with_custom_error<F, T, E>(future: F) -> Promise
where
    F: Future<Output = Result<T, E>> + 'static,
    T: Into<JsValue>,
    E: Into<JsValue>,
{
    let mut future = Some(future.with_current_subscriber());

    Promise::new(&mut |resolve, reject| {
        let future = future.take().unwrap_throw();

        spawn_local(async move {
            match future.await {
                Ok(value) => resolve.call1(&JsValue::UNDEFINED, &value.into()).unwrap_throw(),
                Err(value) => reject.call1(&JsValue::UNDEFINED, &value.into()).unwrap_throw(),
            };
        });
    })
}
