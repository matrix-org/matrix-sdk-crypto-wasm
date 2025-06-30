//! Dehydrated devices
//!
//! WASM wrapper for `matrix_sdk_crypto::dehydrated_devices`.

use js_sys::{Array, JsString, Uint8Array};
use matrix_sdk_crypto::{
    dehydrated_devices, store::types::DehydratedDeviceKey as InnerDehydratedDeviceKey,
};
use wasm_bindgen::prelude::*;

use crate::{identifiers::DeviceId, requests::PutDehydratedDeviceRequest, store::RoomKeyInfo};

#[wasm_bindgen]
#[derive(Debug)]
/// Struct collecting methods to create and rehydrate dehydrated devices.
pub struct DehydratedDevices {
    inner: dehydrated_devices::DehydratedDevices,
}

impl From<dehydrated_devices::DehydratedDevices> for DehydratedDevices {
    fn from(value: dehydrated_devices::DehydratedDevices) -> Self {
        Self { inner: value }
    }
}

/// Dehydrated device key
#[wasm_bindgen]
#[derive(Debug)]
pub struct DehydratedDeviceKey {
    inner: InnerDehydratedDeviceKey,
}

#[wasm_bindgen]
impl DehydratedDeviceKey {
    /// Generates a new random dehydrated device key.
    #[wasm_bindgen(js_name = "createRandomKey")]
    pub fn create_random_key() -> Result<DehydratedDeviceKey, JsError> {
        Ok(DehydratedDeviceKey { inner: InnerDehydratedDeviceKey::new()? })
    }

    /// Generates a dehydrated device key from a given array.
    #[wasm_bindgen(js_name = "createKeyFromArray")]
    pub fn create_key_from_array(array: Uint8Array) -> Result<DehydratedDeviceKey, JsError> {
        Ok(DehydratedDeviceKey {
            inner: InnerDehydratedDeviceKey::from_slice(array.to_vec().as_slice())?,
        })
    }

    /// Convert the dehydrated device key to a base64-encoded string.
    #[wasm_bindgen(js_name = "toBase64")]
    pub fn to_base64(&self) -> JsString {
        self.inner.to_base64().into()
    }
}

impl From<InnerDehydratedDeviceKey> for DehydratedDeviceKey {
    fn from(inner: InnerDehydratedDeviceKey) -> Self {
        DehydratedDeviceKey { inner }
    }
}

#[wasm_bindgen]
impl DehydratedDevices {
    /// Create a new {@link DehydratedDevice} which can be uploaded to the
    /// server.
    #[wasm_bindgen]
    pub async fn create(&self) -> Result<DehydratedDevice, JsError> {
        Ok(self.inner.create().await?.into())
    }

    /// Rehydrate a dehydrated device.
    #[wasm_bindgen]
    pub async fn rehydrate(
        &self,
        dehydrated_device_key: &DehydratedDeviceKey,
        device_id: &DeviceId,
        device_data: &str,
    ) -> Result<RehydratedDevice, JsError> {
        Ok(self
            .inner
            .rehydrate(
                &dehydrated_device_key.inner,
                &device_id.inner,
                serde_json::from_str(device_data)?,
            )
            .await?
            .into())
    }

    /// Get the cached dehydrated device key if any.
    ///
    /// `None` if the key was not previously cached (via
    /// {@link DehydratedDevices.saveDehydratedDeviceKey}).
    #[wasm_bindgen(js_name = "getDehydratedDeviceKey")]
    pub async fn get_dehydrated_device_key(&self) -> Result<Option<DehydratedDeviceKey>, JsError> {
        let key = self.inner.get_dehydrated_device_pickle_key().await?;
        Ok(key.map(DehydratedDeviceKey::from))
    }

    /// Store the dehydrated device key in the crypto store.
    #[wasm_bindgen(js_name = "saveDehydratedDeviceKey")]
    pub async fn save_dehydrated_device_key(
        &self,
        dehydrated_device_key: &DehydratedDeviceKey,
    ) -> Result<(), JsError> {
        self.inner.save_dehydrated_device_pickle_key(&dehydrated_device_key.inner).await?;
        Ok(())
    }

    /// Clear the dehydrated device key saved in the crypto store.
    #[wasm_bindgen(js_name = "deleteDehydratedDeviceKey")]
    pub async fn delete_dehydrated_device_key(&self) -> Result<(), JsError> {
        self.inner.delete_dehydrated_device_pickle_key().await?;
        Ok(())
    }
}

#[wasm_bindgen]
#[derive(Debug)]
/// A rehydrated device
///
/// This device can receive to-device events to get room keys that were send to
/// it.
pub struct RehydratedDevice {
    inner: dehydrated_devices::RehydratedDevice,
}

impl From<dehydrated_devices::RehydratedDevice> for RehydratedDevice {
    fn from(value: dehydrated_devices::RehydratedDevice) -> Self {
        Self { inner: value }
    }
}

#[wasm_bindgen]
impl RehydratedDevice {
    #[wasm_bindgen(js_name = "receiveEvents")]
    /// Receive the to-device events that sent to the dehydrated device
    ///
    /// The rehydrated device will decrypt the events and pass the room keys
    /// into the `OlmMachine`.
    ///
    /// `to_device_events` is a JSON-encoded result of the `events` array from
    /// `/dehydrated_device/{device_id}/events`.
    ///
    /// Returns an array of `RoomKeyInfo`, indicating the room keys that were
    /// received.
    pub async fn receive_events(&self, to_device_events: &str) -> Result<Array, JsError> {
        let to_device_events = serde_json::from_str(to_device_events)?;

        let room_key_info = self.inner.receive_events(to_device_events).await?;
        Ok(room_key_info.into_iter().map(RoomKeyInfo::from).map(JsValue::from).collect())
    }
}

#[wasm_bindgen]
#[derive(Debug)]
/// A dehydrated device that can be uploaded to the server
pub struct DehydratedDevice {
    inner: dehydrated_devices::DehydratedDevice,
}

impl From<dehydrated_devices::DehydratedDevice> for DehydratedDevice {
    fn from(value: dehydrated_devices::DehydratedDevice) -> Self {
        Self { inner: value }
    }
}

#[wasm_bindgen]
impl DehydratedDevice {
    #[wasm_bindgen(js_name = "keysForUpload")]
    /// Create the request to upload the dehydrated device
    pub async fn keys_for_upload(
        &self,
        initial_device_display_name: JsString,
        dehydrated_device_key: &DehydratedDeviceKey,
    ) -> Result<PutDehydratedDeviceRequest, JsError> {
        Ok(self
            .inner
            .keys_for_upload(initial_device_display_name.into(), &dehydrated_device_key.inner)
            .await?
            .try_into()?)
    }
}
