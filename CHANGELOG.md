# UNRELEASED

-   Update matrix-rusk-sdk to `022068996`, which includes:

    -   Send stable identifier `sender_device_keys` for MSC4147 (Including device
        keys with Olm-encrypted events).
        ([#4964](https://github.com/matrix-org/matrix-rust-sdk/pull/4964))

    -   Fix bug which caused room keys to be unnecessarily rotated on every send in the
        presence of blacklisted/withheld devices in the room.
        ([#4954](https://github.com/matrix-org/matrix-rust-sdk/pull/4954))

    -   Fix [#2729](https://github.com/matrix-org/matrix-rust-sdk/issues/2729) which in rare
        cases can cause room key oversharing.
        ([#4975](https://github.com/matrix-org/matrix-rust-sdk/pull/4975))

-   **BREAKING**: `OlmMachine.receiveSyncChanges` now returns a list of
    `ProcessedToDeviceEvent` instead of a JSON-encoded list of JSON-encoded events.
    This allows making the difference between an event that was sent in clear and
    the same event successfully decrypted.
    ([#236](https://github.com/matrix-org/matrix-rust-sdk-crypto-wasm/pull/236))

# matrix-sdk-crypto-wasm v14.2.1

Update matrix-sdk-crypto to `0.11.1`, which includes:

### Security Fixes

-   Check the sender of an event matches owner of session, preventing sender
    spoofing by homeserver owners.
    [13c1d20](https://github.com/matrix-org/matrix-rust-sdk/commit/13c1d2048286bbabf5e7bc6b015aafee98f04d55) (High, [GHSA-x958-rvg6-956w](https://github.com/matrix-org/matrix-rust-sdk/security/advisories/GHSA-x958-rvg6-956w)).

# matrix-sdk-crypto-wasm v14.2.0

-   Log warnings when we fail to parse a backed-up room key
    ([#228](https://github.com/matrix-org/matrix-rust-sdk-crypto-wasm/pull/228))

# matrix-sdk-crypto-wasm v14.1.0

-   Update matrix-rusk-sdk to `0.11.0`, which includes:

    -   Add support for the shared history flag defined in
        [MSC3061](https://github.com/matrix-org/matrix-spec-proposals/pull/3061).
        The shared history flag is now respected when room keys are received as an
        `m.room_key` event as well as when they are imported from a backup or a file
        export.
        ([#4700](https://github.com/matrix-org/matrix-rust-sdk/pull/4700))

-   Add the `PkEncryption`, `PkDecryption`, `Curve25519SecretKey`, `PkMessage`,
    and `Base64EncodedPkMessage` classes. These types implement the
    `m.megolm_backup.v1.curve25519-aes-sha2` algorithm described in the Matrix
    [spec](https://spec.matrix.org/v1.11/client-server-api/#backup-algorithm-mmegolm_backupv1curve25519-aes-sha2).
    ([#209](https://github.com/matrix-org/matrix-rust-sdk-crypto-wasm/pull/209))

# matrix-sdk-crypto-wasm v14.0.1

-   Fix a problem, introduced in v14.0.0, which could cause WASM runtime errors
    if the `OlmMachine` was freed while an operation was in flight.
    ([#205](https://github.com/matrix-org/matrix-rust-sdk-crypto-wasm/pull/205)),
    ([#206](https://github.com/matrix-org/matrix-rust-sdk-crypto-wasm/pull/206))

# matrix-sdk-crypto-wasm v14.0.0

-   `CollectStrategy.deviceBasedStrategy` is deprecated, and replaced by other methods in `CollectStrategy`.
    ([#194](https://github.com/matrix-org/matrix-rust-sdk-crypto-wasm/pull/194))

-   **BREAKING**: Improve generated typescript types (`Promise<T>` instead of
    `Promise<any>`, etc).
    ([#193](https://github.com/matrix-org/matrix-rust-sdk-crypto-wasm/pull/193))

-   Fix a problem, introduced in v12.0.0, when importing the published package as an ESM module, in which some files could be incorrectly interpreted as CommonJS, leading to syntax errors.
    ([#189](https://github.com/matrix-org/matrix-rust-sdk-crypto-wasm/pull/189))

-   Update matrix-rust-sdk to `0.10.0`, which includes:

    -   Accept stable identifier `sender_device_keys` for MSC4147 (Including device
        keys with Olm-encrypted events).
        ([#4420](https://github.com/matrix-org/matrix-rust-sdk/pull/4420))

    -   Room keys are not shared with unsigned dehydrated devices.
        ([#4551](https://github.com/matrix-org/matrix-rust-sdk/pull/4551))

# matrix-sdk-crypto-wasm v13.0.0

-   Update matrix-rusk-sdk to `0.9.0`.
-   Expose new API `DehydratedDevices.getDehydratedDeviceKey`, `DehydratedDevices.saveDehydratedDeviceKey`
    and `DehydratedDevices.deleteDehydratedDeviceKey` to store/load the dehydrated device pickle key.
    ([#179](https://github.com/matrix-org/matrix-rust-sdk-crypto-wasm/pull/179))

**BREAKING CHANGES**

-   `DehydratedDevices.keysForUpload` and `DehydratedDevices.rehydrate` now use a `DehydratedDeviceKey` as parameter
    instead of a raw `UInt8Array`. Use `DehydratedDeviceKey.createKeyFromArray` to migrate.
    ([#179](https://github.com/matrix-org/matrix-rust-sdk-crypto-wasm/pull/179))

# matrix-sdk-crypto-wasm v12.1.0

-   Update matrix-rusk-sdk to `37c17cf854a70f` for the fix for
    https://github.com/matrix-org/matrix-rust-sdk/issues/4424

# matrix-sdk-crypto-wasm v12.0.0

-   Update matrix-rusk-sdk to `e99939db857ca`.
-   The published package is now a proper dual CommonJS/ESM package.
-   The WebAssembly module is now loaded using `fetch` on Web platforms, reducing
    the bundle size significantly, as well as the time it takes to compile it.
    ([#167](https://github.com/matrix-org/matrix-rust-sdk-crypto-wasm/pull/167)),
    ([#174](https://github.com/matrix-org/matrix-rust-sdk-crypto-wasm/pull/174)),
    ([#175](https://github.com/matrix-org/matrix-rust-sdk-crypto-wasm/pull/175))

**BREAKING CHANGES**

-   The WebAssembly module is no longer synchronously loaded on Web platforms
    when used. This means that the `initAsync` function **must** be called before any
    other functions are used. The behaviour is unchanged and still available on
    Node.js.

# matrix-sdk-crypto-wasm v11.0.0

-   Update matrix-rust-sdk to `70bcddfba5e19`.

**BREAKING CHANGES**

-   Remove `SignedCurve25519` variant of `DeviceKeyAlgorithm`.

# matrix-sdk-crypto-wasm v10.1.0

-   Update matrix-rust-sdk to `ce9dc73376b4ee`
-   Update other dependencies

# matrix-sdk-crypto-wasm v10.0.0

**BREAKING CHANGES**

-   Rename `DecryptionErrorCode.SenderIdentityPreviouslyVerified` to
    `SenderIdentityVerificationViolation` (in line with changes to
    matrix-rust-sdk).

-   Rename `UserIdentity` to `OtherUserIdentity` (in line with changes
    to matrix-rust-sdk).

-   Update matrix-rust-sdk to `3558886b9`.

# matrix-sdk-crypto-wasm v9.1.0

-   Update matrix-rust-sdk to `866b6e5f`, which includes:

    -   Change the withheld code for keys not shared due to the `IdentityBasedStrategy`, from `m.unauthorised` to `m.unverified`.
        ([#3985](https://github.com/matrix-org/matrix-rust-sdk/pull/3985))

    -   Improve logging for undecryptable Megolm events.
        ([#3989](https://github.com/matrix-org/matrix-rust-sdk/pull/3989))

# matrix-sdk-crypto-wasm v9.0.0

**BREAKING CHANGES**

-   The `SenderIdentityNotTrusted` value in the `DecryptionErrorCode` was
    replaced with `UnknownSenderDevice`, `UnsignedSenderDevice`, and
    `SenderIdentityPreviouslyVerified` to allow the application to distinguish
    between the different reasons that the sender identity is not trusted.

**Other changes**

-   Add `OlmMachine.markAllTrackedUsersAsDirty` to invalidate the device lists
    for all known users. This is required for [MSC4186](https://github.com/matrix-org/matrix-spec-proposals/pull/4186)
    clients as the server may give up trying to persist device list updates for
    the client at some point, after which the client must treat all devices as dirty.

-   Update matrix-rust-sdk to `2408df8bf`. No changes relevant to these bindings.

# matrix-sdk-crypto-wasm v8.0.0

**BREAKING CHANGES**

-   The format for `EncryptionSettings.sharingStrategy` has changed. It must
    now be created using the `CollectStrategy.deviceBasedStrategy(...)` or
    `CollectStrategy.identityBasedStrategy()` functions.
    ([#141](https://github.com/matrix-org/matrix-rust-sdk-crypto-wasm/pull/141))
-   The `OlmMachine.decryptRoomEvent` has a new `DecryptionSettings` parameter
    that allows specifying the required sender trust level. If the trust level
    is not met, the decryption will fail. To replicate the old behaviour, use a
    sender trust level of `TrustRequirement.Untrusted`.
    ([#141](https://github.com/matrix-org/matrix-rust-sdk-crypto-wasm/pull/141))

**Security Fixes**

-   Fix `UserIdentity.isVerified` to take into account our own identity
    [#d8d9dae](https://github.com/matrix-org/matrix-rust-sdk/commit/d8d9dae9d77bee48a2591b9aad9bd2fa466354cc) (Moderate, [GHSA-4qg4-cvh2-crgg](https://github.com/matrix-org/matrix-rust-sdk/security/advisories/GHSA-4qg4-cvh2-crgg)).

**Other changes**

-   Add `(Own)UserIdentity.wasPreviouslyVerified()`,
    `(Own)UserIdentity.withdrawVerification()`, and
    `(Own)UserIdentity.hasVerificationViolation()` to check and manage the state
    of users who were previously verified but are no longer verified.
    ([#141](https://github.com/matrix-org/matrix-rust-sdk-crypto-wasm/pull/141))
-   Add `UserIdentity.pinCurrentMasterKey()` and
    `UserInfo.identityNeedsUserApproval()` to manage user identity changes.
    ([#141](https://github.com/matrix-org/matrix-rust-sdk-crypto-wasm/pull/141))
-   `ShieldState` has a new `code` property that is set when the shield state is
    not `None`.
    ([#141](https://github.com/matrix-org/matrix-rust-sdk-crypto-wasm/pull/141))
-   Add a new API `Device.encryptToDeviceEvent` to encrypt a to-device message using
    Olm.
    ([#101](https://github.com/matrix-org/matrix-rust-sdk-crypto-wasm/pull/101))

-   Update matrix-rust-sdk to `07aa6d7bc`, which includes:

    -   **NOTE**: this version causes changes to the format of the serialised
        data in the CryptoStore, meaning that, once upgraded, it will not be
        possible to roll back applications to earlier versions without breaking
        user sessions.

    -   Miscellaneous improvements to logging for verification and
        `OwnUserIdentity` updates.
        ([#3949](https://github.com/matrix-org/matrix-rust-sdk/pull/3949))

    -   Add message IDs to all outgoing encrypted to-device messages.
        ([#3776](https://github.com/matrix-org/matrix-rust-sdk/pull/3776))

# matrix-sdk-crypto-wasm v7.0.0

**BREAKING CHANGES**

-   `EncryptionSettings.onlyAllowTrustedDevices` has been replaced with
    `EncryptionSettings.sharingStrategy`, which adds the ability to share only
    with cross-signed devices.
    ([#134](https://github.com/matrix-org/matrix-rust-sdk-crypto-wasm/pull/134))

**Other changes**

-   Add `OlmMachine.registerRoomKeysWithheldCallback` to notify when we are
    told that room keys have been withheld.
    ([#136](https://github.com/matrix-org/matrix-rust-sdk-crypto-wasm/pull/136))

-   Update matrix-rust-sdk to `d9b2b53f8`, which includes:

    -   refactor(sdk-crypto): Room key sharing, introduce extensible strategy
        ([#3605](https://github.com/matrix-org/matrix-rust-sdk/pull/3605))

    -   Log the content of received `m.room_key.withheld` to-device events.
        ([#3591](https://github.com/matrix-org/matrix-rust-sdk/pull/3591))

    -   Attempt to decrypt bundled events (reactions and the latest thread reply) if they are found in the unsigned part of an event.
        ([#3468](https://github.com/matrix-org/matrix-rust-sdk/pull/3468))

# matrix-sdk-crypto-wasm v6.2.1

-   Update matrix-rust-sdk to `7b25a1c2f`, which includes fixes to bugs introduced in v6.2.0.
    ([#3651](https://github.com/matrix-org/matrix-rust-sdk/pull/3651))

# matrix-sdk-crypto-wasm v6.2.0

-   Update matrix-rust-sdk to `09d53a52a`, which includes:

    -   Improve the efficiency of objects stored in the crypto store. ([#3645](https://github.com/matrix-org/matrix-rust-sdk/pull/3645))

# matrix-sdk-crypto-wasm v6.1.0

-   Set "creation time" of `OlmAccount`s which were migrated from legacy libolm data to the unix epoch, instead of "now". Fixes https://github.com/element-hq/element-web/issues/27590.
    ([#128](https://github.com/matrix-org/matrix-rust-sdk-crypto-wasm/pull/128))

-   Update matrix-rust-sdk to `a2235d50c`. No changes relevant to these bindings.

# matrix-sdk-crypto-wasm v6.0.0

**BREAKING CHANGES**

-   Rename the `QrCodeData` related methods so they use camel case.
    ([0d58c688d](https://github.com/matrix-org/matrix-rust-sdk-crypto-wasm/commit/0d58c688454d40269d93fc4f763b2d1a754ace9d))

-   Rename the `QrCodeData.homeserver_url` method to `QrCodeData.server_name`
    to reflect the changed data stored in the QR code.
    ([#124](https://github.com/matrix-org/matrix-rust-sdk-crypto-wasm/pull/124))

-   Update matrix-rust-sdk to `9b05d0d82`, which includes:

    -   `Device.requestVerification`, `UserIdentities.requestVerification`, and
        `UserIdentities.verificationRequestContent` is not async anymore.
        ([#3513](https://github.com/matrix-org/matrix-rust-sdk/pull/3513))

    -   Use the server name in the `QrCodeData` instead of the homeserver URL.
        ([#3537](https://github.com/matrix-org/matrix-rust-sdk/pull/3537))

# matrix-sdk-crypto-wasm v5.0.0

**BREAKING CHANGES**

-   `OlmMachine.importBackedUpRoomKeys` now takes a `backupVersion` argument.

**Other changes**

-   Update matrix-rust-sdk to `7e44fbca7`, which includes:

    -   Avoid emitting entries from `identities_stream_raw` and `devices_stream` when
        we receive a `/keys/query` response which shows that no devices changed.
        ([#3442](https://github.com/matrix-org/matrix-rust-sdk/pull/3442)).

    -   Fix to a bug introduced in matrix-sdk-crypto-wasm v4.10.0 which caused
        keys that had been imported from key backup to be backed up again, when
        using the in-memory datastore.

-   Improve the return types of `OlmMachine.{import,export}exportSecretsBundle()`.
    ([#123](https://github.com/matrix-org/matrix-rust-sdk-crypto-wasm/pull/123))

# matrix-sdk-crypto-wasm v4.10.0

-   Expose new constructor function `OlmMachine.openWithKey()`.
    ([#119](https://github.com/matrix-org/matrix-rust-sdk-crypto-wasm/pull/119))

-   Add `OlmMachine.importSecretsBundle()` and `OlmMachine.exportSecretsBundle()`
    methods as well as the `SecretsBundle` class to import end-to-end encryption
    secrets in a bundled manner.

-   Expose the vodozemac ECIES support, which can be used to establish the secure
    channel required for QR code login described in [MSC4108](https://github.com/matrix-org/matrix-spec-proposals/pull/4108).

-   Add `QrCodeData` and `QrCodeMode` classes which can be used to parse or
    generate QR codes intended for the QR code login mechanism described in
    [MSC4108](https://github.com/matrix-org/matrix-spec-proposals/pull/4108).

-   Add a constructor for the `Curve25519PublicKey` type. This allows us to
    create a `Curve25519PublicKey` from a Base64 string on the Javascript side.

-   Update matrix-rust-sdk to `d7a887766c`, which includes:

    -   Add data types to parse the QR code data for the QR code login defined in
        [MSC4108](https://github.com/matrix-org/matrix-spec-proposals/pull/4108)

    -   Don't log the private part of the backup key, introduced in [#71136e4](https://github.com/matrix-org/matrix-rust-sdk/commit/71136e44c03c79f80d6d1a2446673bc4d53a2067).

    -   Expose new method `CryptoStore::clear_caches`. ([#3338](https://github.com/matrix-org/matrix-rust-sdk/pull/3338))

# matrix-sdk-crypto-wasm v4.9.0

-   Update matrix-rust-sdk to `ab9e4f73b`.

-   Add `OlmMachine.deviceCreationTimeMs`.
    ([#112](https://github.com/matrix-org/matrix-rust-sdk-crypto-wasm/pull/112))

# matrix-sdk-crypto-wasm v4.8.0

-   Update matrix-rust-sdk to `6aee1f62bd`, which includes:

    -   Fallback keys are rotated in a time-based manner, instead of waiting for
        the server to tell us that a fallback key got used.
        ([#3151](https://github.com/matrix-org/matrix-rust-sdk/pull/3151))

    -   Log more details about the Olm session after encryption and decryption.
        ([#3242](https://github.com/matrix-org/matrix-rust-sdk/pull/3242))

    -   When Olm message decryption fails, report the error code(s) from the
        failure.
        ([#3212](https://github.com/matrix-org/matrix-rust-sdk/pull/3212))

-   Add `OlmMachine.dehydratedDevices()` and `DehydratedDevices` class to
    support dehydrated devices.
    ([#104](https://github.com/matrix-org/matrix-rust-sdk-crypto-wasm/pull/104))

-   Fix a problem when using matrix-sdk-crypto-wasm in a webapp running
    in the webpack dev server; when rebuilding, the server would throw an
    error.
    ([#109](https://github.com/matrix-org/matrix-rust-sdk-crypto-wasm/pull/109))

# matrix-sdk-crypto-wasm v4.7.0

-   Update dependencies, including matrix-rust-sdk to
    88a8a7007ca34408af21c7e0bee81b2c344b155c which provides the
    `_disable-minimum-rotation-period-ms` feature flag.

# matrix-sdk-crypto-wasm v4.6.0

-   Update dependencies, including matrix-rust-sdk to
    dcf00697539321cf4eac5cd4929d45347b947da7
    Use the new export_room_keys_stream method to reduce one copy of the keys
    made during export.

# matrix-sdk-crypto-wasm v4.5.0

-   Update dependencies, including matrix-rust-sdk to
    5957d9603bd8a3f00ddd9a52bda80224c853bcd1 to get
    https://github.com/matrix-org/matrix-rust-sdk/pull/3095 which speeds up the
    schema upgrade v8->v10 again. See
    https://github.com/element-hq/element-web/issues/26948

# matrix-sdk-crypto-wasm v4.4.0

-   Update dependencies, including matrix-rust-sdk to
    87a07d9ee32e576963c2e55889bbb504d4bb4ede to get
    https://github.com/matrix-org/matrix-rust-sdk/pull/3090 which speeds up the
    schema upgrade v8->v10. See
    https://github.com/element-hq/element-web/issues/26948

# matrix-sdk-crypto-wasm v4.3.0

-   Update `matrix-rust-sdk` version (f64af126f1a618969737f6eacc87427db106224e)
    to get https://github.com/matrix-org/matrix-rust-sdk/pull/3073 which
    improves Indexed DB performance by moving to schema v10.

# matrix-sdk-crypto-wasm v4.2.0

-   Update `matrix-rust-sdk` version (f5f8f47667f686d7937d4d31040032281fcf2cfc)

# matrix-sdk-crypto-wasm v4.1.0

-   Add `Unknown` to `EncryptionAlgorithm`, representing unsupported algorithms
    coming from matrix-sdk-crypto's `EventEncryptionAlgorithm`.
    ([#92](https://github.com/matrix-org/matrix-rust-sdk-crypto-wasm/pull/92))

-   Add new methods `OlmMachine.{get,set}RoomSettings`.
    ([#95](https://github.com/matrix-org/matrix-rust-sdk-crypto-wasm/pull/95))

-   Add `OlmMachine.registerDevicesUpdatedCallback` to notify when devices have
    been updated.
    ([#88](https://github.com/matrix-org/matrix-rust-sdk-crypto-wasm/pull/88))

# matrix-sdk-crypto-wasm v4.0.1

-   `PickledInboundGroupSession.sender_signing_key` is now optional.
    ([#89](https://github.com/matrix-org/matrix-rust-sdk-crypto-wasm/pull/89))

-   Properly encode missing and `Duration` parameters in requests.
    ([#72](https://github.com/matrix-org/matrix-rust-sdk-crypto-wasm/pull/72))

# matrix-sdk-crypto-wasm v4.0.0

**BREAKING CHANGES**

-   Rename `OlmMachine.init_from_store` introduced in v3.6.0 to
    `OlmMachine.initFromStore`.
    ([#84](https://github.com/matrix-org/matrix-rust-sdk-crypto-wasm/pull/84))

-   Functions/methods that take a JavaScript `Array` as argument now invalidate the
    items within that array so that they cannot be re-used as soon as
    they are received by the functions/methods. See the patch for affected methods.
    ([#82](https://github.com/matrix-org/matrix-rust-sdk-crypto-wasm/pull/82/))

**Other changes**

-   Update `wasm-bindgen` to 0.2.89. It allows to remove the `downcast` method.
    It fixes [#51](https://github.com/matrix-org/matrix-rust-sdk-crypto-wasm/pull/51),
    thus the resulting JavaScript code of `matrix-rust-sdk-crypto-wasm` can
    be minified with no issue now.
    ([#82](https://github.com/matrix-org/matrix-rust-sdk-crypto-wasm/pull/82/))

-   Report failures to callback when importing backed-up room keys. The
    `progress_listener` callback in the `OlmMachine.importBackedUpRoomKeys`
    function is now called with a third argument, giving the number of invalid
    room keys.
    ([#85](https://github.com/matrix-org/matrix-rust-sdk-crypto-wasm/pull/85))

# matrix-sdk-crypto-wasm v3.6.0

-   Add a `Migration` class, supporting importing account and session data from
    libolm.
    ([#77](https://github.com/matrix-org/matrix-rust-sdk-crypto-wasm/pull/77))

-   Add a `StoreHandle` class which can be used to hold a connection to a
    crypto store, and thus improve performance when doing multiple operations
    on the store.
    ([#76](https://github.com/matrix-org/matrix-rust-sdk-crypto-wasm/pull/76))

-   Update `matrix-rust-sdk` version, with changes including:
    -   Fix for an issue which caused the same keys to be repeatedly backed up.
        ([matrix-rust-sdk#2937](https://github.com/matrix-org/matrix-rust-sdk/pull/2957))
    -   Performance improvement in `markRequestAsSent`.
        ([matrix-rust-sdk#2977](https://github.com/matrix-org/matrix-rust-sdk/pull/2977))
    -   Logging for the open sequence for indexeddb store.
        ([matrix-rust-sdk#2983](https://github.com/matrix-org/matrix-rust-sdk/pull/2983))

# matrix-sdk-crypto-wasm v3.5.0

-   Update matrix-rust-sdk version, providing several changes including a fix
    for occasional freezes (https://github.com/element-hq/element-web/issues/26488).

-   New API `OlmMachine.requestMissingSecretsIfNeeded` that creates an
    outgoing secret request to other sessions.

-   Verification cancel codes for `cancelWithCode` and `cancelInfo.cancelCode`
    are now passed as strings rather than an enum.

# matrix-sdk-crypto-wasm v3.4.0

-   Include Rust symbol names in the generated wasm output.
    ([#65](https://github.com/matrix-org/matrix-rust-sdk-crypto-wasm/pull/65))

# matrix-sdk-crypto-wasm v3.3.0

-   Add new properties `roomKeyRequestsEnabled` and `roomKeyForwardingEnabled`
    to OlmMachine.
    ([#60](https://github.com/matrix-org/matrix-rust-sdk-crypto-wasm/pull/60),
    ([matrix-rust-sdk#2902](https://github.com/matrix-org/matrix-rust-sdk/pull/2902))

# matrix-sdk-crypto-wasm v3.2.0

-   Add `timeout_secs` parameters to `OlmMachine.get_user_devices` and
    `OlmMachine.get_device`. ([#60](https://github.com/matrix-org/matrix-rust-sdk-crypto-wasm/pull/60))

-   Improve efficiency of IndexedDB storage of `inbound_group_sessions`.
    ([matrix-rust-sdk#2885](https://github.com/matrix-org/matrix-rust-sdk/pull/2885))

# matrix-sdk-crypto-wasm v3.1.0

-   Improve performance of `OlmMachine.shareRoomKey`.
    ([matrix-rust-sdk#2862](https://github.com/matrix-org/matrix-rust-sdk/pull/2862))

-   `OlmMachine.getMissingSessions`: Don't block waiting for `/keys/query`
    requests on blacklisted servers, and improve performance.
    ([matrix-rust-sdk#2845](https://github.com/matrix-org/matrix-rust-sdk/pull/2845))

-   Various clarifications to the log messages written during encryption operations.
    ([matrix-rust-sdk#2859](https://github.com/matrix-org/matrix-rust-sdk/pull/2859))

-   `OlmMachine.importRoomKeys` is now deprecated in favour of separate
    methods for importing room keys from backup and export,
    `OlmMachine.importBackedUpRoomKeys` and
    `OlmMachine.importExportedRoomKeys`.

-   Minor improvements to the formatting of messages logged to the console.

# matrix-sdk-crypto-wasm v3.0.1

**BREAKING CHANGES**

-   `OlmMachine.bootstrapCrossSigning` no longer returns an array of request
    objects. Rather, it returns a new class (`CrossSigningBootstrapRequests`)
    which contains the request objects within it.

    As part of this work, `SigningKeysUploadRequest` (which was one of the
    types formerly returned by `bootstrapCrossSigning`) has been renamed to
    `UploadSigningKeysRequest` for consistency with the underlying SDK.

## Other changes

-   Devices which have exhausted their one-time-keys will now be correctly
    handled in `/keys/claim` responses (we will register them as "failed" and
    stop attempting to send to them for a while.)

-   Olm decryption operations will no longer log large quantities of data about
    the data `Store`.

# matrix-sdk-crypto-wasm v3.0.0

Do not use this release. It has a [critical bug](https://github.com/matrix-org/matrix-rust-sdk/issues/2802).

# matrix-sdk-crypto-wasm v2.2.0

-   Added bindings versions details to `getVersions()`. Two new fields `git_sha` and
    `git_description` have been included in the returned `Versions` struct.

# matrix-sdk-crypto-wasm v2.1.1

## Changes in the underlying Rust crate

-   Clean up the logging of to-device messages in `share_room_key`. Also fixes
    some `panic` errors which were introduced in v2.1.0.

-   Remove spurious "Unknown outgoing secret request" warning which was logged
    for every outgoing secret request.

-   Various other changes.

# matrix-sdk-crypto-wasm v2.1.0

-   Attach message IDs to outgoing to-device messages, and log the IDs on
    incoming messages.

-   Improve logging output to include more information, including data that is
    attached to tracing spans. Remove the `tracing` feature: tracing support is
    now always included.

-   BugFix: `ToDeviceRequest` returned by `shareRoomKey(..)` always had an `undefined` `id` field.

# matrix-sdk-crypto-wasm v2.0.0

-   Updated rust sdk version to revision [c2bb76029ae6d99c741727e0f87abcd734377016](https://github.com/matrix-org/matrix-rust-sdk/commit/c2bb76029ae6d99c741727e0f87abcd734377016), including:
    -   [Remove dashmap crate usage from matrix-sdk-crypto](https://github.com/matrix-org/matrix-rust-sdk/pull/2669)
    -   [Bugfix for invalidated private cross signing keys not being persisted](https://github.com/matrix-org/matrix-rust-sdk/pull/2676)
-   API Break: `RoomId.localpart` and `RoomId.serverName` have been removed.
-   Add new secrets API `OlmMachine.registerReceiveSecretCallback`,
    `OlmMachine.getSecretsFromInbox`, `OlmMachine.deleteSecretsFromInbox`.

# matrix-sdk-crypto-wasm v1.3.0

-   Add `OlmMachine.registerUserIdentityUpdatedCallback`.
-   Expose new method `OlmMachine.getRoomEventEncryptionInfo`.
-   Update `IndexeddbCryptoStore` to use a single store for outgoing secret
    requests.

# matrix-sdk-crypto-wasm v1.2.2

## Changes in the WASM bindings

-   `OlmMachine.decrypt_room_event()` now throws a
    typed `MegolmDecryptionError` instead of generic `Error`.

# matrix-sdk-crypto-wasm v1.2.1

## Changes in the WASM bindings

-   Expose `version` field of `KeysBackupRequest`.

# matrix-sdk-crypto-wasm v1.2.0

## Changes in the WASM bindings

-   The `BackupKeys` structure returned by `OlmMachine.getBackupKeys` now
    contains a `decryptionKey` property which is is a `BackupDecryptionKey`
    instance.

-   Expose `SignatureVerification.trusted` method.

# matrix-sdk-crypto-wasm v1.1.0

## Changes in the WASM bindings

-   Expose bindings for secure key backup.
-   Expose `OwnUserIdentity.isVerified`.

## Changes in the underlying Rust crate

-   Mark our `OwnUserIdentity` as verified if we successfully import the matching private keys.

# matrix-sdk-crypto-wasm v1.0.1

No functional changes. Fixes for the release process which prevented v1.0.0
being released.

# matrix-sdk-crypto-wasm v1.0.0

Project renamed to `matrix-sdk-crypto-wasm`. No functional changes.

# matrix-sdk-crypto-js v0.1.4

-   Add method `OlmMachine.queryKeysForUsers` to build an out-of-band key
    request.

# matrix-sdk-crypto-js v0.1.3

## Changes in the Javascript bindings

-   Fix bug introduced in v0.1.2 which caused an undocumented change to the results of `OlmMachine.receiveSyncChanges`.

## Changes in the underlying Rust crate

-   Fix a bug which could cause generated one-time-keys not to be persisted.

# matrix-sdk-crypto-js v0.1.2

**WARNING**: this version had a breaking change in the result type of `OlmMachine.receiveSyncChanges`.
This is corrected in v0.1.3.

## Changes in the Javascript bindings

-   Add `Qr.state()` method to inspect the current state of QR code
    verifications.

## Changes in the underlying Rust crate

-   Fix handling of SAS verification start events once we have shown a QR code.

# matrix-sdk-crypto-js v0.1.1

-   Add `verify` method to `Device`.

# matrix-sdk-crypto-js v0.1.0

## Changes in the Javascript bindings

-   In `OlmMachine.getIdentity`, wait a limited time for any in-flight
    device-list updates to complete.

-   Add `VerificationRequest.timeRemainingMillis()`.

## Changes in the underlying Rust crate

-   When rejecting a key-verification request over to-device messages, send the
    `m.key.verification.cancel` to the device that made the request, rather
    than broadcasting to all devices.

# matrix-sdk-crypto-js v0.1.0-alpha.11

## Changes in the Javascript bindings

-   Simplify the response type of `Sas.confirm()`.
-   Add `VerificationRequest.registerChangesCallback()`,
    `Sas.registerChangesCallback()`, and `Qr.registerChangesCallback()`.
-   Add `VerificationRequest.phase()` and `VerificationRequest.getVerification()`.

## Changes in the underlying Rust crate

-   Add support for the `hkdf-hmac-sha256.v2` SAS message authentication code.

-   Ensure that the correct short authentication strings are used when accepting a
    SAS verification with the `Sas::accept()` method.

# matrix-sdk-crypto-js v0.1.0-alpha.10

-   Add `masterKey`, `userSigningKey`, `selfSigningKey` to `UserIdentity` and `OwnUserIdentity`

# matrix-sdk-crypto-js v0.1.0-alpha.9

-   Extend `OlmDevice.markRequestAsSent` to accept responses to
    `SigningKeysUploadRequest`s.
-   Add a missing `const` for compatibility with ECMAScript Module compatibility
    mode.
-   Fix the body of `SignatureUploadRequest`s to match the spec.
-   Add a constructor for `SigningKeysUploadRequest`.

# matrix-sdk-crypto-js v0.1.0-alpha.8

-   `importCrossSigningKeys`: change the parameters to be individual keys
    rather than a `CrossSigningKeyExport` object.
-   Make `unused_fallback_keys` optional in `Machine.receive_sync_changes`

# matrix-sdk-crypto-js v0.1.0-alpha.7

-   Add new accessors `Device.algorithms` and `Device.isSignedByOwner`
-   In `OlmMachine.getUserDevices`, wait a limited time for any in-flight
    device-list updates to complete.

# matrix-sdk-crypto-js v0.1.0-alpha.6

-   Add new accessor `InboundGroupSession.senderKey`.
-   Add a new API, `OlmMachine.registerRoomKeyUpdatedCallback`, which
    applications can use to listen for received room keys.
