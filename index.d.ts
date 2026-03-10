// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/*
 * Re-export all the type definitions that wasm-bindgen generated for us.
 *
 * We do this by referring to a non-existent "matrix_sdk_crypto_wasm.js" file. This works because TSC will automatically
 * transform this into the correct name "matrix_sdk_crypto_wasm.d.ts" [1].
 *
 * Other alternatives don't work:
 *
 *  - `export * from "./pkg/matrix_sdk_crypto_wasm.d.ts"`: You're not allowed to `import from "<foo>.d.ts"`
 *    without `import type`, because normally, that would mean you don't get the runtime definitions that are in
 *    "<foo>.js". This lint rule even applies to ".d.ts" files, which is arguably overzealous, but there you have it.
 *
 *  - `export type * from "./pkg/matrix_sdk_crypto_wasm.d.ts"`: Doing this means you can't call the constructors on any
 *    of the exported types: `new RoomId(...)` gives a build error.
 *
 *  - `export * from "./pkg/matrix_sdk_crypto_wasm"`: This works in *some* environments, but in others, typescript
 *    complains [2]. We could maybe get around this by mandating a `moduleResolution` setting of `bundler` or so, but
 *    that is restrictive on our downstreams.
 *
 * A final alternative would be just to cat `matrix_sdk_crypto_wasm.d.ts` in here as part of the build script, but
 * for now at least we're trying to avoid too much file manipulation.
 *
 * [1]: https://www.typescriptlang.org/docs/handbook/modules/reference.html#file-extension-substitution
 * [2]: https://www.typescriptlang.org/docs/handbook/modules/reference.html#extensionless-relative-paths
 */
export * from "./pkg/matrix_sdk_crypto_wasm.js";

/**
 * Load the WebAssembly module in the background, if it has not already been loaded.
 *
 * Returns a promise which will resolve once the other methods are ready.
 * @param {URL | string} [url] - The URL to fetch the WebAssembly module from. If not provided, a default URL will be used.
 * @returns {Promise<void>}
 */
export declare function initAsync(url?: URL | string): Promise<void>;

// The auto-generated typescript definitions are a good start, but could do with tightening up in a lot of areas.
// The following is a manually-curated set of typescript definitions.
declare module "./pkg/matrix_sdk_crypto_wasm.js" {
    interface JsLogger {
        debug(data: any): void;
        info(data: any): void;
        warn(data: any): void;
        error(data: any): void;
    }

    /** The types returned by {@link OlmMachine.outgoingRequests}. */
    type OutgoingRequest =
        | KeysUploadRequest
        | KeysQueryRequest
        | KeysClaimRequest
        | ToDeviceRequest
        | SignatureUploadRequest
        | RoomMessageRequest
        | KeysBackupRequest;

    /** The types returned by {@link OlmMachine.receiveSyncChanges}. */
    type ProcessedToDeviceEvent =
        | DecryptedToDeviceEvent
        | PlainTextToDeviceEvent
        | InvalidToDeviceEvent
        | UTDToDeviceEvent;

    interface OlmMachine {
        trackedUsers(): Promise<Set<UserId>>;
        updateTrackedUsers(users: UserId[]): Promise<void>;
        receiveSyncChanges(
            to_device_events: string,
            changed_devices: DeviceLists,
            one_time_keys_counts: Map<string, number>,
            unused_fallback_keys?: Set<string> | null,
            decryption_settings?: DecryptionSettings,
        ): Promise<Array<ProcessedToDeviceEvent>>;
        outgoingRequests(): Promise<Array<OutgoingRequest>>;
        markRequestAsSent(request_id: string, request_type: RequestType, response: string): Promise<boolean>;
        encryptRoomEvent(room_id: RoomId, event_type: string, content: string): Promise<string>;
        decryptRoomEvent(
            event: string,
            room_id: RoomId,
            decryption_settings: DecryptionSettings,
        ): Promise<DecryptedRoomEvent>;
        getRoomEventEncryptionInfo(event: string, room_id: RoomId): Promise<EncryptionInfo>;
        crossSigningStatus(): Promise<CrossSigningStatus>;
        exportCrossSigningKeys(): Promise<CrossSigningKeyExport | undefined>;
        importCrossSigningKeys(
            master_key?: string | null,
            self_signing_key?: string | null,
            user_signing_key?: string | null,
        ): Promise<CrossSigningStatus>;
        bootstrapCrossSigning(reset: boolean): Promise<CrossSigningBootstrapRequests>;
        sign(message: string): Promise<Signatures>;
        invalidateGroupSession(room_id: RoomId): Promise<boolean>;
        shareRoomKey(room_id: RoomId, users: UserId[], encryption_settings: EncryptionSettings): Promise<Array<any>>;
        getMissingSessions(users: UserId[]): Promise<KeysClaimRequest | undefined>;
        getUserDevices(user_id: UserId, timeout_secs?: number | null): Promise<UserDevices>;
        getDevice(user_id: UserId, device_id: DeviceId, timeout_secs?: number | null): Promise<Device | undefined>;
        receiveVerificationEvent(event: string, room_id: RoomId): Promise<void>;
        exportRoomKeys(predicate: Function): Promise<string>;
        importRoomKeys(exported_room_keys: string, progress_listener: Function): Promise<string>;
        importExportedRoomKeys(exported_room_keys: string, progress_listener: Function): Promise<RoomKeyImportResult>;
        importBackedUpRoomKeys(
            backed_up_room_keys: Map<any, any>,
            progress_listener: Function | null | undefined,
            backup_version: string,
        ): Promise<RoomKeyImportResult>;
        saveBackupDecryptionKey(decryption_key: BackupDecryptionKey, version: string): Promise<void>;
        getBackupKeys(): Promise<BackupKeys>;
        verifyBackup(backup_info: any): Promise<SignatureVerification>;
        enableBackupV1(public_key_base_64: string, version: string): Promise<void>;
        isBackupEnabled(): Promise<boolean>;
        disableBackup(): Promise<void>;
        backupRoomKeys(): Promise<KeysBackupRequest | undefined>;
        roomKeyCounts(): Promise<RoomKeyCounts>;
        getSecretsFromInbox(secret_name: string): Promise<Set<any>>;
        deleteSecretsFromInbox(secret_name: string): Promise<void>;
        requestMissingSecretsIfNeeded(): Promise<boolean>;
    }
}
