import {
    BackupDecryptionKey,
    CrossSigningStatus,
    DecryptedRoomEvent,
    DecryptedToDeviceEvent,
    DecryptionErrorCode,
    DecryptionSettings,
    DeviceId,
    DeviceKeyId,
    DeviceLists,
    EncryptionAlgorithm,
    EncryptionSettings,
    EventId,
    getVersions,
    InboundGroupSession,
    InvalidToDeviceEvent,
    KeysBackupRequest,
    KeysClaimRequest,
    KeysQueryRequest,
    KeysUploadRequest,
    MaybeSignature,
    MegolmDecryptionError,
    OlmMachine,
    OtherUserIdentity,
    OwnUserIdentity,
    PlainTextToDeviceEvent,
    ProcessedToDeviceEventType,
    RequestType,
    RoomId,
    RoomKeyWithheldInfo,
    RoomMessageRequest,
    RoomSettings,
    ShieldColor,
    ShieldStateCode,
    SignatureState,
    SignatureUploadRequest,
    StoreHandle,
    ToDeviceRequest,
    TrustRequirement,
    UserId,
    UTDToDeviceEvent,
    VerificationRequest,
    Versions,
} from "@matrix-org/matrix-sdk-crypto-wasm";
import "fake-indexeddb/auto";
import * as crypto from "node:crypto";

type AnyOutgoingRequest =
    | KeysUploadRequest
    | KeysQueryRequest
    | KeysClaimRequest
    | ToDeviceRequest
    | SignatureUploadRequest
    | RoomMessageRequest
    | KeysBackupRequest;

afterEach(() => {
    // reset fake-indexeddb after each test, to make sure we don't leak data
    // cf https://github.com/dumbmatter/fakeIndexedDB#wipingresetting-the-indexeddb-for-a-fresh-state
    // eslint-disable-next-line no-global-assign
    indexedDB = new IDBFactory();
});

describe("Versions", () => {
    test("can find out the crate versions", async () => {
        const versions = getVersions();

        expect(versions).toBeInstanceOf(Versions);
        expect(versions.vodozemac).toBeDefined();
        expect(versions.matrix_sdk_crypto).toBeDefined();
        expect(versions.git_sha).toBeDefined();
        expect(versions.git_description).toBeDefined();
    });
});

jest.setTimeout(15000);

const EXPECTED_DB_VERSION = 102;

describe(OlmMachine.name, () => {
    test("can be instantiated with the async initializer", async () => {
        expect(await OlmMachine.initialize(new UserId("@foo:bar.org"), new DeviceId("baz"))).toBeInstanceOf(OlmMachine);
    });

    test("can be instantiated with a StoreHandle", async () => {
        let storeName = "hello";
        let storePassphrase = "world";

        let storeHandle = await StoreHandle.open(storeName, storePassphrase);
        expect(
            await OlmMachine.initFromStore(new UserId("@foo:bar.org"), new DeviceId("baz"), storeHandle),
        ).toBeInstanceOf(OlmMachine);
        storeHandle.free();
    });

    test("can be instantiated with passphrase", async () => {
        let storeName = "hello2";
        let storePassphrase = "world";

        const byStoreName = (db: IDBDatabaseInfo) => db.name!.startsWith(storeName);

        // No databases.
        expect((await indexedDB.databases()).filter(byStoreName)).toHaveLength(0);

        // Creating a new Olm machine.
        expect(
            await OlmMachine.initialize(new UserId("@foo:bar.org"), new DeviceId("baz"), storeName, storePassphrase),
        ).toBeInstanceOf(OlmMachine);

        // Oh, there is 2 databases now, prefixed by `storeName`.
        let databases = (await indexedDB.databases()).filter(byStoreName);

        expect(databases).toHaveLength(2);
        expect(databases).toStrictEqual([
            { name: `${storeName}::matrix-sdk-crypto-meta`, version: 1 },
            { name: `${storeName}::matrix-sdk-crypto`, version: EXPECTED_DB_VERSION },
        ]);

        // Creating a new Olm machine, with the stored state.
        expect(
            await OlmMachine.initialize(new UserId("@foo:bar.org"), new DeviceId("baz"), storeName, storePassphrase),
        ).toBeInstanceOf(OlmMachine);

        // Same number of databases.
        expect((await indexedDB.databases()).filter(byStoreName)).toHaveLength(2);
    });

    test("can be instantiated with a passphrase, and then migrated to a key", async () => {
        const storeName = "hello3";
        const pickleKey = new Uint8Array(32);
        crypto.getRandomValues(pickleKey);

        const b64Pickle = Buffer.from(pickleKey)
            .toString("base64")
            .replace(/={1,2}$/, "");
        const storeHandle = await StoreHandle.open(storeName, b64Pickle);
        const olmMachine: OlmMachine = await OlmMachine.initFromStore(
            new UserId("@foo:bar.org"),
            new DeviceId("baz"),
            storeHandle,
        );
        storeHandle.free();
        expect(olmMachine).toBeInstanceOf(OlmMachine);
        const deviceKeys = olmMachine.identityKeys;

        // re-open the store, using the key directly
        const storeHandle2 = await StoreHandle.openWithKey(storeName, pickleKey);
        const olmMachine2: OlmMachine = await OlmMachine.initFromStore(
            new UserId("@foo:bar.org"),
            new DeviceId("baz"),
            storeHandle2,
        );
        storeHandle2.free();
        expect(olmMachine2).toBeInstanceOf(OlmMachine);

        // make sure that we got back the same device.
        const deviceKeys2 = olmMachine2.identityKeys;
        expect(deviceKeys2.ed25519.toBase64()).toEqual(deviceKeys.ed25519.toBase64());
    });

    describe("cannot be instantiated with a store", () => {
        test("store name is missing", async () => {
            let storePassphrase = "world";

            let err = null;

            try {
                await OlmMachine.initialize(
                    new UserId("@foo:bar.org"),
                    new DeviceId("baz"),
                    undefined,
                    storePassphrase,
                );
            } catch (error) {
                err = error;
            }

            expect(err).toBeDefined();
        });

        test("store passphrase is missing", async () => {
            let storeName = "hello";

            let err = null;

            try {
                await OlmMachine.initialize(new UserId("@foo:bar.org"), new DeviceId("baz"), storeName, undefined);
            } catch (error) {
                err = error;
            }

            expect(err).toBeDefined();
        });
    });

    const user = new UserId("@alice:example.org");
    const device = new DeviceId("foobar");
    const room = new RoomId("!baz:matrix.org");

    function machine(newUser?: UserId, newDevice?: DeviceId): Promise<OlmMachine> {
        // Uncomment to enable debug logging for tests
        // new RustSdkCryptoJs.Tracing(RustSdkCryptoJs.LoggerLevel.Trace).turnOn();
        return OlmMachine.initialize(newUser || user, newDevice || device);
    }

    test("can drop/close", async () => {
        const m = await machine();
        m.close();
    });

    test("can drop/close with a store", async () => {
        let storeName = "temporary";
        let storePassphrase = "temporary";

        const byStoreName = (db: IDBDatabaseInfo) => db.name?.startsWith(storeName);

        // No databases.
        expect((await indexedDB.databases()).filter(byStoreName)).toHaveLength(0);

        // Creating a new Olm machine.
        const m = await OlmMachine.initialize(
            new UserId("@foo:bar.org"),
            new DeviceId("baz"),
            storeName,
            storePassphrase,
        );
        expect(m).toBeInstanceOf(OlmMachine);

        // Oh, there is 2 databases now, prefixed by `storeName`.
        let databases = (await indexedDB.databases()).filter(byStoreName);

        expect(databases).toHaveLength(2);
        expect(databases).toStrictEqual([
            { name: `${storeName}::matrix-sdk-crypto-meta`, version: 1 },
            { name: `${storeName}::matrix-sdk-crypto`, version: EXPECTED_DB_VERSION },
        ]);

        // Let's force to close the `OlmMachine`.
        m.close();

        // Now we can delete the databases!
        for (const databaseName of [`${storeName}::matrix-sdk-crypto`, `${storeName}::matrix-sdk-crypto-meta`]) {
            const deleting = indexedDB.deleteDatabase(databaseName);
            deleting.onsuccess = () => {};
            deleting.onerror = () => {
                throw new Error("failed to remove the database (error)");
            };
            deleting.onblocked = () => {
                throw new Error("failed to remove the database (blocked)");
            };
        }
    });

    test("can read user ID", async () => {
        expect((await machine()).userId.toString()).toStrictEqual(user.toString());
    });

    test("can read device ID", async () => {
        expect((await machine()).deviceId.toString()).toStrictEqual(device.toString());
    });

    test("can read creation time", async () => {
        const startTime = Date.now();
        const creationTime = (await machine()).deviceCreationTimeMs;
        expect(creationTime).toBeLessThanOrEqual(Date.now());
        expect(creationTime).toBeGreaterThanOrEqual(startTime);
    });

    test("can read identity keys", async () => {
        const identityKeys = (await machine()).identityKeys;

        expect(identityKeys.ed25519.toBase64()).toMatch(/^[A-Za-z0-9+/]+$/);
        expect(identityKeys.curve25519.toBase64()).toMatch(/^[A-Za-z0-9+/]+$/);
    });

    // This returns the empty object for some reason?
    test.skip("can read display name", async () => {
        expect((await machine()).displayName).toBeUndefined();
    });

    test("can toggle room key requests", async () => {
        const m = await machine();
        expect(m.roomKeyRequestsEnabled).toBe(true);
        m.roomKeyRequestsEnabled = false;
        expect(m.roomKeyRequestsEnabled).toBe(false);
    });

    test("can toggle room key forwarding", async () => {
        const m = await machine();
        expect(m.roomKeyForwardingEnabled).toBe(true);
        m.roomKeyForwardingEnabled = false;
        expect(m.roomKeyForwardingEnabled).toBe(false);
    });

    test("can read tracked users", async () => {
        const m = await machine();
        const trackedUsers = await m.trackedUsers();

        expect(trackedUsers).toBeInstanceOf(Set);
        expect(trackedUsers.size).toStrictEqual(0);
    });

    test("can update tracked users", async () => {
        const m = await machine();

        expect(await m.updateTrackedUsers([user.clone()])).toStrictEqual(undefined);
    });

    test("can receive sync changes", async () => {
        const m = await machine();
        const toDeviceEvents = JSON.stringify([]);
        const changedDevices = new DeviceLists();
        const oneTimeKeyCounts = new Map();
        const unusedFallbackKeys = new Set();

        const receiveSyncChanges = await m.receiveSyncChanges(
            toDeviceEvents,
            changedDevices,
            oneTimeKeyCounts,
            unusedFallbackKeys,
        );
        expect(receiveSyncChanges).toEqual([]);
    });

    test("can receive sync changes with unusedFallbackKeys as undefined", async () => {
        const m = await machine();
        const toDeviceEvents = JSON.stringify([]);
        const changedDevices = new DeviceLists();
        const oneTimeKeyCounts = new Map();

        const receiveSyncChanges = await m.receiveSyncChanges(
            toDeviceEvents,
            changedDevices,
            oneTimeKeyCounts,
            undefined,
        );
        expect(receiveSyncChanges).toEqual([]);
    });

    test("can get the outgoing requests that need to be sent out", async () => {
        const m = await machine();
        const toDeviceEvents = JSON.stringify([]);
        const changedDevices = new DeviceLists();
        const oneTimeKeyCounts = new Map();
        const unusedFallbackKeys = new Set();

        const receiveSyncChanges = await m.receiveSyncChanges(
            toDeviceEvents,
            changedDevices,
            oneTimeKeyCounts,
            unusedFallbackKeys,
        );
        expect(receiveSyncChanges).toEqual([]);

        const outgoingRequests = await m.outgoingRequests();

        expect(outgoingRequests).toHaveLength(2);

        {
            expect(outgoingRequests[0]).toBeInstanceOf(KeysUploadRequest);
            expect(outgoingRequests[0].id).toBeDefined();
            expect(outgoingRequests[0].type).toStrictEqual(RequestType.KeysUpload);
            expect(outgoingRequests[0].body).toBeDefined();

            const body = JSON.parse(outgoingRequests[0].body);
            expect(body.device_keys).toBeDefined();
            expect(body.one_time_keys).toBeDefined();
        }

        {
            expect(outgoingRequests[1]).toBeInstanceOf(KeysQueryRequest);
            expect(outgoingRequests[1].id).toBeDefined();
            expect(outgoingRequests[1].type).toStrictEqual(RequestType.KeysQuery);
            expect(outgoingRequests[1].body).toBeDefined();

            const body = JSON.parse(outgoingRequests[1].body);
            // default timeout in Rust is None, so timeout will be omitted
            expect(body.timeout).not.toBeDefined();
            expect(body.device_keys).toBeDefined();
        }
    });

    test("Can build a key query request", async () => {
        const m = await machine();
        const request = m.queryKeysForUsers([new UserId("@alice:example.org")]);
        expect(request).toBeInstanceOf(KeysQueryRequest);
        const body = JSON.parse(request.body);
        expect(Object.keys(body.device_keys)).toContain("@alice:example.org");
    });

    describe("setup workflow to mark requests as sent", () => {
        let m: OlmMachine;
        let outgoingRequests: Array<AnyOutgoingRequest>;

        beforeAll(async () => {
            m = await machine(new UserId("@alice:example.org"), new DeviceId("DEVICEID"));

            const toDeviceEvents = JSON.stringify([]);
            const changedDevices = new DeviceLists();
            const oneTimeKeyCounts = new Map();
            const unusedFallbackKeys = new Set();

            const receiveSyncChanges = await m.receiveSyncChanges(
                toDeviceEvents,
                changedDevices,
                oneTimeKeyCounts,
                unusedFallbackKeys,
            );
            outgoingRequests = await m.outgoingRequests();

            expect(outgoingRequests).toHaveLength(2);
        });

        test("can mark requests as sent", async () => {
            {
                const request = outgoingRequests[0];
                expect(request).toBeInstanceOf(KeysUploadRequest);

                // https://spec.matrix.org/v1.2/client-server-api/#post_matrixclientv3keysupload
                const hypotheticalResponse = JSON.stringify({
                    one_time_key_counts: {
                        curve25519: 10,
                        signed_curve25519: 20,
                    },
                });
                const marked = await m.markRequestAsSent(request.id!, request.type, hypotheticalResponse);
                expect(marked).toStrictEqual(true);
            }

            {
                const request = outgoingRequests[1];
                expect(request).toBeInstanceOf(KeysQueryRequest);

                // https://spec.matrix.org/v1.2/client-server-api/#post_matrixclientv3keysquery
                const hypotheticalResponse = JSON.stringify({
                    device_keys: {
                        "@alice:example.org": {
                            JLAFKJWSCS: {
                                algorithms: ["m.olm.v1.curve25519-aes-sha2", "m.megolm.v1.aes-sha2"],
                                device_id: "JLAFKJWSCS",
                                keys: {
                                    "curve25519:JLAFKJWSCS": "wjLpTLRqbqBzLs63aYaEv2Boi6cFEbbM/sSRQ2oAKk4",
                                    "ed25519:JLAFKJWSCS": "nE6W2fCblxDcOFmeEtCHNl8/l8bXcu7GKyAswA4r3mM",
                                },
                                signatures: {
                                    "@alice:example.org": {
                                        "ed25519:JLAFKJWSCS":
                                            "m53Wkbh2HXkc3vFApZvCrfXcX3AI51GsDHustMhKwlv3TuOJMj4wistcOTM8q2+e/Ro7rWFUb9ZfnNbwptSUBA",
                                    },
                                },
                                unsigned: {
                                    device_display_name: "Alice's mobile phone",
                                },
                                user_id: "@alice:example.org",
                            },
                        },
                    },
                    failures: {},
                });
                const marked = await m.markRequestAsSent(request.id!, request.type, hypotheticalResponse);
                expect(marked).toStrictEqual(true);
            }
        });
    });

    describe("setup workflow to encrypt/decrypt events", () => {
        let m: OlmMachine;
        const user = new UserId("@alice:example.org");
        const device = new DeviceId("JLAFKJWSCS");
        const room = new RoomId("!test:localhost");

        beforeAll(async () => {
            m = await machine(user, device);
        });

        test("can pass keysquery and keysclaim requests directly", async () => {
            {
                // derived from https://github.com/matrix-org/matrix-rust-sdk/blob/7f49618d350fab66b7e1dc4eaf64ec25ceafd658/benchmarks/benches/crypto_bench/keys_query.json
                const hypotheticalResponse = JSON.stringify({
                    device_keys: {
                        "@example:localhost": {
                            AFGUOBTZWM: {
                                algorithms: ["m.olm.v1.curve25519-aes-sha2", "m.megolm.v1.aes-sha2"],
                                device_id: "AFGUOBTZWM",
                                keys: {
                                    "curve25519:AFGUOBTZWM": "boYjDpaC+7NkECQEeMh5dC+I1+AfriX0VXG2UV7EUQo",
                                    "ed25519:AFGUOBTZWM": "NayrMQ33ObqMRqz6R9GosmHdT6HQ6b/RX/3QlZ2yiec",
                                },
                                signatures: {
                                    "@example:localhost": {
                                        "ed25519:AFGUOBTZWM":
                                            "RoSWvru1jj6fs2arnTedWsyIyBmKHMdOu7r9gDi0BZ61h9SbCK2zLXzuJ9ZFLao2VvA0yEd7CASCmDHDLYpXCA",
                                    },
                                },
                                user_id: "@example:localhost",
                                unsigned: {
                                    device_display_name: "rust-sdk",
                                },
                            },
                        },
                    },
                    failures: {},
                    master_keys: {
                        "@example:localhost": {
                            user_id: "@example:localhost",
                            usage: ["master"],
                            keys: {
                                "ed25519:n2lpJGx0LiKnuNE1IucZP3QExrD4SeRP0veBHPe3XUU":
                                    "n2lpJGx0LiKnuNE1IucZP3QExrD4SeRP0veBHPe3XUU",
                            },
                            signatures: {
                                "@example:localhost": {
                                    "ed25519:TCSJXPWGVS":
                                        "+j9G3L41I1fe0++wwusTTQvbboYW0yDtRWUEujhwZz4MAltjLSfJvY0hxhnz+wHHmuEXvQDen39XOpr1p29sAg",
                                },
                            },
                        },
                    },
                    self_signing_keys: {
                        "@example:localhost": {
                            user_id: "@example:localhost",
                            usage: ["self_signing"],
                            keys: {
                                "ed25519:kQXOuy639Yt47mvNTdrIluoC6DMvfbZLYbxAmwiDyhI":
                                    "kQXOuy639Yt47mvNTdrIluoC6DMvfbZLYbxAmwiDyhI",
                            },
                            signatures: {
                                "@example:localhost": {
                                    "ed25519:n2lpJGx0LiKnuNE1IucZP3QExrD4SeRP0veBHPe3XUU":
                                        "q32ifix/qyRpvmegw2BEJklwoBCAJldDNkcX+fp+lBA4Rpyqtycxge6BA4hcJdxYsy3oV0IHRuugS8rJMMFyAA",
                                },
                            },
                        },
                    },
                    user_signing_keys: {
                        "@example:localhost": {
                            user_id: "@example:localhost",
                            usage: ["user_signing"],
                            keys: {
                                "ed25519:g4ED07Fnqf3GzVWNN1pZ0IFrPQVdqQf+PYoJNH4eE0s":
                                    "g4ED07Fnqf3GzVWNN1pZ0IFrPQVdqQf+PYoJNH4eE0s",
                            },
                            signatures: {
                                "@example:localhost": {
                                    "ed25519:n2lpJGx0LiKnuNE1IucZP3QExrD4SeRP0veBHPe3XUU":
                                        "nKQu8alQKDefNbZz9luYPcNj+Z+ouQSot4fU/A23ELl1xrI06QVBku/SmDx0sIW1ytso0Cqwy1a+3PzCa1XABg",
                                },
                            },
                        },
                    },
                });
                const marked = await m.markRequestAsSent("foo", RequestType.KeysQuery, hypotheticalResponse);
            }

            {
                // derived from https://github.com/matrix-org/matrix-rust-sdk/blob/7f49618d350fab66b7e1dc4eaf64ec25ceafd658/benchmarks/benches/crypto_bench/keys_claim.json
                const hypotheticalResponse = JSON.stringify({
                    one_time_keys: {
                        "@example:localhost": {
                            AFGUOBTZWM: {
                                "signed_curve25519:AAAABQ": {
                                    key: "9IGouMnkB6c6HOd4xUsNv4i3Dulb4IS96TzDordzOws",
                                    signatures: {
                                        "@example:localhost": {
                                            "ed25519:AFGUOBTZWM":
                                                "2bvUbbmJegrV0eVP/vcJKuIWC3kud+V8+C0dZtg4dVovOSJdTP/iF36tQn2bh5+rb9xLlSeztXBdhy4c+LiOAg",
                                        },
                                    },
                                },
                            },
                        },
                    },
                    failures: {},
                });
                const marked = await m.markRequestAsSent("bar", RequestType.KeysClaim, hypotheticalResponse);
            }
        });

        test("can share a room key", async () => {
            const other_user_id = new UserId("@example:localhost");

            const requests = await m.shareRoomKey(room, [other_user_id.clone()], new EncryptionSettings());

            expect(requests).toHaveLength(1);
            expect(requests[0]).toBeInstanceOf(ToDeviceRequest);
            expect(requests[0].event_type).toEqual("m.room.encrypted");
            expect(requests[0].txn_id).toBeDefined();
            expect(requests[0].id).toBeDefined();
            const content = JSON.parse(requests[0].body);
            expect(Object.keys(content.messages)).toEqual(["@example:localhost"]);
            const messageContent = content.messages["@example:localhost"]["AFGUOBTZWM"];
            expect(messageContent["org.matrix.msgid"]).toBeDefined();

            await m.markRequestAsSent(requests[0].id, RequestType.ToDevice, "{}");

            const requestsAfterMarkedAsSent = await m.shareRoomKey(
                room,
                [other_user_id.clone()],
                new EncryptionSettings(),
            );
            expect(requestsAfterMarkedAsSent).toHaveLength(0);
        });

        let encrypted: Record<string, any>;

        test("can encrypt an event", async () => {
            encrypted = JSON.parse(
                await m.encryptRoomEvent(
                    room,
                    "m.room.message",
                    JSON.stringify({
                        msgtype: "m.text",
                        body: "Hello, World!",
                    }),
                ),
            );

            expect(encrypted.algorithm).toBeDefined();
            expect(encrypted.ciphertext).toBeDefined();
            expect(encrypted.sender_key).toBeDefined();
            expect(encrypted.device_id).toStrictEqual(device.toString());
            expect(encrypted.session_id).toBeDefined();
        });

        test("can decrypt an event", async () => {
            const stringifiedEvent = JSON.stringify({
                type: "m.room.encrypted",
                event_id: "$xxxxx:example.org",
                origin_server_ts: Date.now(),
                sender: user.toString(),
                content: encrypted,
                unsigned: {
                    age: 1234,
                },
            });

            const decryptionSettings = new DecryptionSettings(TrustRequirement.Untrusted);
            const decrypted = await m.decryptRoomEvent(stringifiedEvent, room, decryptionSettings)!;
            expect(decrypted).toBeInstanceOf(DecryptedRoomEvent);

            const event = JSON.parse(decrypted.event);
            expect(event.content.msgtype).toStrictEqual("m.text");
            expect(event.content.body).toStrictEqual("Hello, World!");

            expect(decrypted.sender?.toString()).toStrictEqual(user.toString());
            expect(decrypted.senderDevice?.toString()).toStrictEqual(device.toString());
            expect(decrypted.senderCurve25519Key).toBeDefined();
            expect(decrypted.senderClaimedEd25519Key).toBeDefined();
            expect(decrypted.forwardingCurve25519KeyChain).toHaveLength(0);
            expect(decrypted.shieldState(true)?.color).toStrictEqual(ShieldColor.Red);
            expect(decrypted.shieldState(true)?.code).toStrictEqual(ShieldStateCode.UnverifiedIdentity);
            expect(decrypted.shieldState(false)?.color).toStrictEqual(ShieldColor.Red);
            expect(decrypted.shieldState(false)?.code).toStrictEqual(ShieldStateCode.UnsignedDevice);

            const decryptionInfo = await m.getRoomEventEncryptionInfo(stringifiedEvent, room);
            expect(decryptionInfo.sender?.toString()).toStrictEqual(user.toString());
            expect(decryptionInfo.senderDevice?.toString()).toStrictEqual(device.toString());
            expect(decryptionInfo.senderCurve25519Key).toBeDefined();
            expect(decryptionInfo.senderClaimedEd25519Key).toBeDefined();
            expect(decryptionInfo.shieldState(true)?.color).toStrictEqual(ShieldColor.Red);
            expect(decryptionInfo.shieldState(true)?.code).toStrictEqual(ShieldStateCode.UnverifiedIdentity);
            expect(decryptionInfo.shieldState(false)?.color).toStrictEqual(ShieldColor.Red);
            expect(decryptionInfo.shieldState(false)?.code).toStrictEqual(ShieldStateCode.UnsignedDevice);
        });

        test("can encrypt a state event", async () => {
            encrypted = JSON.parse(
                await m.encryptStateEvent(
                    room,
                    "m.room.topic",
                    "",
                    JSON.stringify({
                        topic: "It's a secret!",
                    }),
                ),
            );

            expect(encrypted.algorithm).toBeDefined();
            expect(encrypted.ciphertext).toBeDefined();
            expect(encrypted.sender_key).toBeDefined();
            expect(encrypted.device_id).toStrictEqual(device.toString());
            expect(encrypted.session_id).toBeDefined();
        });

        test("can decrypt a state event", async () => {
            const stringifiedEvent = JSON.stringify({
                type: "m.room.encrypted",
                event_id: "$xxxxx:example.org",
                origin_server_ts: Date.now(),
                sender: user.toString(),
                content: encrypted,
                state_key: "m.room.topic:",
                unsigned: {
                    age: 1234,
                },
            });

            const decryptionSettings = new DecryptionSettings(TrustRequirement.Untrusted);
            const decrypted = await m.decryptRoomEvent(stringifiedEvent, room, decryptionSettings)!;
            expect(decrypted).toBeInstanceOf(DecryptedRoomEvent);

            const event = JSON.parse(decrypted.event);
            expect(event.content.topic).toStrictEqual("It's a secret!");

            expect(decrypted.sender?.toString()).toStrictEqual(user.toString());
            expect(decrypted.senderDevice?.toString()).toStrictEqual(device.toString());
            expect(decrypted.senderCurve25519Key).toBeDefined();
            expect(decrypted.senderClaimedEd25519Key).toBeDefined();
            expect(decrypted.forwardingCurve25519KeyChain).toHaveLength(0);
            expect(decrypted.shieldState(true)?.color).toStrictEqual(ShieldColor.Red);
            expect(decrypted.shieldState(true)?.code).toStrictEqual(ShieldStateCode.UnverifiedIdentity);
            expect(decrypted.shieldState(false)?.color).toStrictEqual(ShieldColor.Red);
            expect(decrypted.shieldState(false)?.code).toStrictEqual(ShieldStateCode.UnsignedDevice);

            const decryptionInfo = await m.getRoomEventEncryptionInfo(stringifiedEvent, room);
            expect(decryptionInfo.sender?.toString()).toStrictEqual(user.toString());
            expect(decryptionInfo.senderDevice?.toString()).toStrictEqual(device.toString());
            expect(decryptionInfo.senderCurve25519Key).toBeDefined();
            expect(decryptionInfo.senderClaimedEd25519Key).toBeDefined();
            expect(decryptionInfo.shieldState(true)?.color).toStrictEqual(ShieldColor.Red);
            expect(decryptionInfo.shieldState(true)?.code).toStrictEqual(ShieldStateCode.UnverifiedIdentity);
            expect(decryptionInfo.shieldState(false)?.color).toStrictEqual(ShieldColor.Red);
            expect(decryptionInfo.shieldState(false)?.code).toStrictEqual(ShieldStateCode.UnsignedDevice);
        });
    });

    test("failure to decrypt returns a valid error", async () => {
        const m = await machine();
        const evt = {
            type: "m.room.encrypted",
            event_id: "$xxxxx:example.org",
            origin_server_ts: Date.now(),
            sender: user.toString(),
            content: {
                algorithm: "m.megolm.v1.aes-sha2",
                ciphertext: "blah",
            },
        };
        try {
            const decryptionSettings = new DecryptionSettings(TrustRequirement.Untrusted);
            await m.decryptRoomEvent(JSON.stringify(evt), room, decryptionSettings);
            fail("it should not reach here");
        } catch (err) {
            expect(err).toBeInstanceOf(MegolmDecryptionError);
            expect((err as MegolmDecryptionError).code).toStrictEqual(DecryptionErrorCode.UnableToDecrypt);
        }
    });

    test("can read cross-signing status", async () => {
        const m = await machine();
        const crossSigningStatus = await m.crossSigningStatus();

        expect(crossSigningStatus).toBeInstanceOf(CrossSigningStatus);
        expect(crossSigningStatus.hasMaster).toStrictEqual(false);
        expect(crossSigningStatus.hasSelfSigning).toStrictEqual(false);
        expect(crossSigningStatus.hasUserSigning).toStrictEqual(false);
    });

    test("can sign a message", async () => {
        const m = await machine();
        const signatures = await m.sign("foo");

        expect(signatures.isEmpty()).toStrictEqual(false);
        expect(signatures.count).toStrictEqual(1);

        let base64;

        // `get`
        {
            const signature = signatures.get(user);

            expect(signature?.has("ed25519:foobar")).toStrictEqual(true);

            const s = signature?.get("ed25519:foobar");

            expect(s).toBeInstanceOf(MaybeSignature);

            expect(s.isValid()).toStrictEqual(true);
            expect(s.isInvalid()).toStrictEqual(false);
            expect(s.invalidSignatureSource).toBeUndefined();

            base64 = s.signature.toBase64();

            expect(base64).toMatch(/^[A-Za-z0-9\+/]+$/);
            expect(s.signature.ed25519.toBase64()).toStrictEqual(base64);
        }

        // `getSignature`
        {
            const signature = signatures.getSignature(user, new DeviceKeyId("ed25519:foobar"));
            expect(signature?.toBase64()).toStrictEqual(base64);
        }

        // Unknown signatures.
        {
            expect(signatures.get(new UserId("@hello:example.org"))).toBeUndefined();
            expect(signatures.getSignature(user, new DeviceKeyId("world:foobar"))).toBeUndefined();
        }
    });

    test("can mark all tracked users as dirty", async () => {
        const m = await machine();
        await m.markAllTrackedUsersAsDirty();
    });

    test("can get own user identity", async () => {
        const m = await machine();
        let _ = m.bootstrapCrossSigning(true);

        const identity = await m.getIdentity(user);

        expect(identity.isVerified()).toStrictEqual(true);
        expect(identity.wasPreviouslyVerified()).toStrictEqual(true);
        expect(identity.hasVerificationViolation()).toStrictEqual(false);

        expect(identity).toBeInstanceOf(OwnUserIdentity);
        const masterKey = JSON.parse(identity.masterKey);
        const selfSigningKey = JSON.parse(identity.selfSigningKey);
        const userSigningKey = JSON.parse(identity.userSigningKey);

        const masterObjKeys = Object.keys(masterKey.keys);
        const keyFromMasterKey = masterKey.keys[masterObjKeys[0]];

        // self signing key exists
        expect(Object.keys(selfSigningKey.keys).length).toBe(1);
        // self signing key is different from the master key
        expect(selfSigningKey.keys[keyFromMasterKey]).not.toBeDefined();

        const selfSigningObjKeys = Object.keys(selfSigningKey.keys);
        const keyFromSelfSigningKey = masterKey.keys[selfSigningObjKeys[0]];

        // user signing key exists
        expect(Object.keys(userSigningKey.keys).length).toBe(1);
        // user signing key is different from the master key
        expect(userSigningKey.keys[keyFromMasterKey]).not.toBeDefined();
        // user signing key is different from the self signing key
        expect(userSigningKey.keys[keyFromSelfSigningKey]).not.toBeDefined();

        const signatureUploadRequest = await identity.verify();
        expect(signatureUploadRequest).toBeInstanceOf(SignatureUploadRequest);

        const [verificationRequest, outgoingVerificationRequest] = await identity.requestVerification();
        expect(verificationRequest).toBeInstanceOf(VerificationRequest);
        expect(outgoingVerificationRequest).toBeInstanceOf(ToDeviceRequest);

        const isTrusted = await identity.trustsOurOwnDevice();

        expect(isTrusted).toStrictEqual(false);
    });

    test("Updating user identity should call userIdentityUpdatedCallback", async () => {
        const m = await machine();
        let _ = m.bootstrapCrossSigning(true);
        const identity = await m.getIdentity(user);
        expect(identity).toBeInstanceOf(OwnUserIdentity);

        const callback = jest.fn().mockImplementation(() => Promise.resolve(undefined));
        m.registerUserIdentityUpdatedCallback(callback);

        await identity.verify();

        expect(callback).toHaveBeenCalledTimes(1);
        const [userId] = callback.mock.calls[0];
        expect(userId.toString()).toEqual(user.toString());
    });

    test("Receiving a withheld message should call roomKeysWithheldCallback", async () => {
        const m = await machine();

        const callback = jest.fn().mockImplementation(() => Promise.resolve(undefined));
        await m.registerRoomKeysWithheldCallback(callback);

        let toDeviceEvents = [
            {
                sender: "@alice:example.com",
                type: "m.room_key.withheld",
                content: {
                    algorithm: "m.megolm.v1.aes-sha2",
                    code: "m.unverified",
                    reason: "Device not verified",
                    room_id: "!Cuyf34gef24t:localhost",
                    sender_key: "RF3s+E7RkTQTGF2d8Deol0FkQvgII2aJDf3/Jp5mxVU",
                    session_id: "X3lUlvLELLYxeTx4yOVu6UDpasGEVO0Jbu+QFnm0cKQ",
                },
            },
        ];
        await m.receiveSyncChanges(
            JSON.stringify(toDeviceEvents),
            new DeviceLists(),
            new Map<string, number>(),
            undefined,
        );

        expect(callback).toHaveBeenCalledTimes(1);
        const withheld: RoomKeyWithheldInfo[] = callback.mock.calls[0][0];
        expect(withheld[0].sender.toString()).toEqual("@alice:example.com");
        expect(withheld[0].roomId.toString()).toEqual("!Cuyf34gef24t:localhost");
        expect(withheld[0].sessionId).toEqual("X3lUlvLELLYxeTx4yOVu6UDpasGEVO0Jbu+QFnm0cKQ");
        expect(withheld[0].withheldCode).toEqual("m.unverified");
    });

    test("decrypting a message from a withheld session throws MegolmDecryptionError with correct withheld code", async () => {
        const m = await machine();

        // Simulate receiving a withheld event for a session
        const withheldEvent = {
            sender: "@alice:example.com",
            type: "m.room_key.withheld",
            content: {
                algorithm: "m.megolm.v1.aes-sha2",
                code: "m.unverified",
                reason: "Device not verified",
                room_id: room.toString(),
                sender_key: m.identityKeys.curve25519.toBase64(),
                session_id: "SESSION_ID_WITHHELD",
            },
        };
        await m.receiveSyncChanges(
            JSON.stringify([withheldEvent]),
            new DeviceLists(),
            new Map<string, number>(),
            undefined,
        );

        // Now try to decrypt a message from that session
        const encryptedEvent = {
            type: "m.room.encrypted",
            event_id: "$xxxxx:example.org",
            origin_server_ts: Date.now(),
            sender: user.toString(),
            content: {
                algorithm: "m.megolm.v1.aes-sha2",
                ciphertext:
                    "AwgAEpABhetEzzZzyYrxtEVUtlJnZtJcURBlQUQJ9irVeklCTs06LwgTMQj61PMUS4VyYOX+PD67+hhU40/8olOww+Ud0m2afjMjC3wFX+4fFfSkoWPVHEmRVucfcdSF1RSB4EmKPIP4eo1X6x8kCIMewBvxl2sI9j4VNvDvAN7M3zkLJfFLOFHbBviI4FN7hSFHFeM739ZgiwxEs3hIkUXEiAfrobzaMEM/zY7SDrTdyffZndgJo7CZOVhoV6vuaOhmAy4X2t4UnbuVJGJjKfV57NAhp8W+9oT7ugwO",
                sender_key: m.identityKeys.curve25519.toBase64(),
                session_id: "SESSION_ID_WITHHELD",
            },
            unsigned: {
                age: 1234,
            },
        };

        try {
            const decryptionSettings = new DecryptionSettings(TrustRequirement.Untrusted);
            await m.decryptRoomEvent(JSON.stringify(encryptedEvent), room, decryptionSettings);
            fail("Expected MegolmDecryptionError to be thrown");
        } catch (err) {
            expect(err).toBeInstanceOf(MegolmDecryptionError);
            expect((err as MegolmDecryptionError).code).toStrictEqual(DecryptionErrorCode.MissingRoomKey);
            expect((err as MegolmDecryptionError).maybe_withheld).toEqual(
                "The sender has disabled encrypting to unverified devices.",
            );
            expect((err as MegolmDecryptionError).withheldCode).toEqual("m.unverified");
        }
    });

    test("can export room keys", async () => {
        let m = await machine();
        await m.shareRoomKey(room, [new UserId("@bob:example.org")], new EncryptionSettings());

        let exportedRoomKeys = await m.exportRoomKeys((session: InboundGroupSession) => {
            expect(session).toBeInstanceOf(InboundGroupSession);
            expect(session.senderKey.toBase64()).toEqual(m.identityKeys.curve25519.toBase64());
            expect(session.roomId.toString()).toStrictEqual(room.toString());
            expect(session.sessionId).toBeDefined();
            expect(session.hasBeenImported()).toStrictEqual(false);

            return true;
        });

        const roomKeys = JSON.parse(exportedRoomKeys);
        expect(roomKeys).toHaveLength(1);
        expect(roomKeys[0]).toMatchObject({
            algorithm: expect.any(String),
            room_id: room.toString(),
            sender_key: expect.any(String),
            session_id: expect.any(String),
            session_key: expect.any(String),
            sender_claimed_keys: {
                ed25519: expect.any(String),
            },
            forwarding_curve25519_key_chain: [],
        });
    });

    describe("can process exported room keys", () => {
        let exportedRoomKeys: string;

        beforeEach(async () => {
            let m = await machine();
            await m.shareRoomKey(room, [new UserId("@bob:example.org")], new EncryptionSettings());

            exportedRoomKeys = await m.exportRoomKeys(() => true);
        });

        test("can encrypt and decrypt the exported room keys", () => {
            let encryptionPassphrase = "Hello, Matrix!";
            let encryptedExportedRoomKeys = OlmMachine.encryptExportedRoomKeys(
                exportedRoomKeys,
                encryptionPassphrase,
                100000,
            );

            expect(encryptedExportedRoomKeys).toMatch(/^-----BEGIN MEGOLM SESSION DATA-----/);

            const decryptedExportedRoomKeys = OlmMachine.decryptExportedRoomKeys(
                encryptedExportedRoomKeys,
                encryptionPassphrase,
            );

            expect(decryptedExportedRoomKeys).toStrictEqual(exportedRoomKeys);
        });

        test("can import room keys via importRoomKeys", async () => {
            const progressListener = (progress: bigint, total: bigint) => {
                expect(progress).toBeLessThan(total);

                // Since it's called only once, let's be crazy.
                expect(progress).toStrictEqual(0);
                expect(total).toStrictEqual(1);
            };

            let m = await machine();
            const result = JSON.parse(await m.importRoomKeys(exportedRoomKeys, progressListener));

            expect(result).toMatchObject({
                imported_count: expect.any(Number),
                total_count: expect.any(Number),
                keys: expect.any(Object),
            });
        });

        test("can import room keys via importExportedRoomKeys", async () => {
            const progressListener = (progress: bigint, total: bigint) => {
                expect(progress).toStrictEqual(0);
                expect(total).toStrictEqual(1);
            };

            let m = await machine();
            const result = await m.importExportedRoomKeys(exportedRoomKeys, progressListener);

            expect(result.importedCount).toStrictEqual(1);
            expect(result.totalCount).toStrictEqual(1);
            expect(result.keys()).toMatchObject(
                new Map([[room.toString(), new Map([[expect.any(String), new Set([expect.any(String)])]])]]),
            );
        });

        test("importing room keys calls RoomKeyUpdatedCallback", async () => {
            const callback = jest.fn();
            callback.mockImplementation(() => Promise.resolve(undefined));
            let m = await machine();
            m.registerRoomKeyUpdatedCallback(callback);
            await m.importRoomKeys(exportedRoomKeys, () => undefined);
            expect(callback).toHaveBeenCalledTimes(1);
            let keyInfoList = callback.mock.calls[0][0];
            expect(keyInfoList.length).toEqual(1);
            expect(keyInfoList[0].roomId.toString()).toStrictEqual(room.toString());
        });
    });

    describe("can do in-room verification", () => {
        let m: OlmMachine;
        const user = new UserId("@alice:example.org");
        const device = new DeviceId("JLAFKJWSCS");
        const room = new RoomId("!test:localhost");

        beforeAll(async () => {
            m = await machine(user, device);
        });

        test("can inject devices from someone else", async () => {
            {
                const hypotheticalResponse = JSON.stringify({
                    device_keys: {
                        "@example:morpheus.localhost": {
                            ATRLDCRXAC: {
                                algorithms: ["m.olm.v1.curve25519-aes-sha2", "m.megolm.v1.aes-sha2"],
                                device_id: "ATRLDCRXAC",
                                keys: {
                                    "curve25519:ATRLDCRXAC": "cAVT5Es3Z3F5pFD+2w3HT7O9+R3PstzYVkzD51X/FWQ",
                                    "ed25519:ATRLDCRXAC": "V2w/T/x7i7AXiCCtS6JldrpbvRliRoef3CqTUNqMRHA",
                                },
                                signatures: {
                                    "@example:morpheus.localhost": {
                                        "ed25519:ATRLDCRXAC":
                                            "ro2BjO5J6089B/JOANHnFmGrogrC2TIdMlgJbJO00DjOOcGxXfvOezCFIORTwZNHvkHU617YIGl/4keTDIWvBQ",
                                    },
                                },
                                user_id: "@example:morpheus.localhost",
                                unsigned: {
                                    device_display_name: "Element Desktop: Linux",
                                },
                            },
                            EYYGYTCTNC: {
                                algorithms: ["m.olm.v1.curve25519-aes-sha2", "m.megolm.v1.aes-sha2"],
                                device_id: "EYYGYTCTNC",
                                keys: {
                                    "curve25519:EYYGYTCTNC": "Pqu50fo472wgb6NjKkaUxjuqoAIEAmhln2gw/zSQ7Ek",
                                    "ed25519:EYYGYTCTNC": "Pf/2QPvui8lDty6TCTglVPRVM+irNHYavNNkyv5yFpU",
                                },
                                signatures: {
                                    "@example:morpheus.localhost": {
                                        "ed25519:EYYGYTCTNC":
                                            "pnP5BYLEUUaxDgrvdzCznkjNDbvY1/MFBr1JejdnLiXlcmxRULQpIWZUCO7QTbULsCwMsYQNGn50nfmjBQX3CQ",
                                    },
                                },
                                user_id: "@example:morpheus.localhost",
                                unsigned: {
                                    device_display_name: "WeeChat-Matrix-rs",
                                },
                            },
                            SUMODVLSIU: {
                                algorithms: ["m.olm.v1.curve25519-aes-sha2", "m.megolm.v1.aes-sha2"],
                                device_id: "SUMODVLSIU",
                                keys: {
                                    "curve25519:SUMODVLSIU": "geQXWGWc++gcUHk0JcFmEVSjyzDOnk2mjVsUQwbNqQU",
                                    "ed25519:SUMODVLSIU": "ccktaQ3g+B18E6FwVhTBYie26OlHbvDUzDEtxOQ4Qcs",
                                },
                                signatures: {
                                    "@example:morpheus.localhost": {
                                        "ed25519:SUMODVLSIU":
                                            "Yn+AOxHRt1GQpY2xT2Jcqqn8jh5+Vw23ctA7NXyDiWPsLPLNTpjGWHMjZdpUqflQvpiKfhODPICoIa7Pu0iSAg",
                                        "ed25519:rUiMNDjIu6gqsrhJPbj3phyIzuEtuQGrLOEa9mCbtTM":
                                            "Cio6k/sq289XNTOvTCWre7Q6zg+A3euzMUe7Uy1T3gPqYFzX+kt7EAxrhbPqx1HyXAEz9zD0D/uw9VEXFCvWBQ",
                                    },
                                },
                                user_id: "@example:morpheus.localhost",
                                unsigned: {
                                    device_display_name: "Element Desktop (Linux)",
                                },
                            },
                        },
                    },
                    failures: {},
                    master_keys: {
                        "@example:morpheus.localhost": {
                            user_id: "@example:morpheus.localhost",
                            usage: ["master"],
                            keys: {
                                "ed25519:ZzU4WCyBfOFitdGmfKCq6F39iQCDk/zhNNTsi+tWH7A":
                                    "ZzU4WCyBfOFitdGmfKCq6F39iQCDk/zhNNTsi+tWH7A",
                            },
                            signatures: {
                                "@example:morpheus.localhost": {
                                    "ed25519:SUMODVLSIU":
                                        "RL6WOuuzB/mZ+edfUFG/KeEcmKh+NaWpM6m2bUYmDnJrtTCYyoU+pgHJuL2/6nynemmONo18JEHBuqtNcMq2AQ",
                                },
                            },
                        },
                    },
                    self_signing_keys: {
                        "@example:morpheus.localhost": {
                            user_id: "@example:morpheus.localhost",
                            usage: ["self_signing"],
                            keys: {
                                "ed25519:rUiMNDjIu6gqsrhJPbj3phyIzuEtuQGrLOEa9mCbtTM":
                                    "rUiMNDjIu6gqsrhJPbj3phyIzuEtuQGrLOEa9mCbtTM",
                            },
                            signatures: {
                                "@example:morpheus.localhost": {
                                    "ed25519:ZzU4WCyBfOFitdGmfKCq6F39iQCDk/zhNNTsi+tWH7A":
                                        "uCBn9rpeg6umY8H97ejN26UMp6QDwNL98869t1DoVGL50J8adLN05OZd8lYk9QzwTr2d56ZTGYSYX8kv28SDDA",
                                },
                            },
                        },
                    },
                    user_signing_keys: {
                        "@example:morpheus.localhost": {
                            user_id: "@example:morpheus.localhost",
                            usage: ["user_signing"],
                            keys: {
                                "ed25519:GLhEKLQ50jnF6IMEPsO2ucpHUNIUEnbBXs5gYbHg4Aw":
                                    "GLhEKLQ50jnF6IMEPsO2ucpHUNIUEnbBXs5gYbHg4Aw",
                            },
                            signatures: {
                                "@example:morpheus.localhost": {
                                    "ed25519:ZzU4WCyBfOFitdGmfKCq6F39iQCDk/zhNNTsi+tWH7A":
                                        "4fIyWlVzuz1pgoegNLZASycORXqKycVS0dNq5vmmwsVEudp1yrPhndnaIJ3fjF8LDHvwzXTvohOid7DiU1j0AA",
                                },
                            },
                        },
                    },
                });
                const marked = await m.markRequestAsSent("foo", RequestType.KeysQuery, hypotheticalResponse);
            }
        });

        test("can start and cancel an in-room SAS verification", async () => {
            let _ = m.bootstrapCrossSigning(true);
            const identity = await m.getIdentity(new UserId("@example:morpheus.localhost"));

            expect(identity).toBeInstanceOf(OtherUserIdentity);
            expect(identity.isVerified()).toStrictEqual(false);
            expect(identity.wasPreviouslyVerified()).toStrictEqual(false);
            expect(identity.hasVerificationViolation()).toStrictEqual(false);
            expect(identity.identityNeedsUserApproval()).toStrictEqual(false);

            const eventId = new EventId("$Rqnc-F-dvnEYJTyHq_iKxU2bZ1CI92-kuZq3a5lr5Zg");
            const verificationRequest = await identity.requestVerification(room, eventId);
            expect(verificationRequest).toBeInstanceOf(VerificationRequest);

            await m.receiveVerificationEvent(
                JSON.stringify({
                    sender: "@example:morpheus.localhost",
                    type: "m.key.verification.ready",
                    event_id: "$QguWmaeMt6Hao7Ea6XHDInvr8ndknev79t9a2eBxlz0",
                    origin_server_ts: 1674037263075,
                    content: {
                        "methods": ["m.sas.v1", "m.qr_code.show.v1", "m.reciprocate.v1"],
                        "from_device": "SUMODVLSIU",
                        "m.relates_to": {
                            rel_type: "m.reference",
                            event_id: eventId.toString(),
                        },
                    },
                }),
                room,
            );

            expect(verificationRequest.roomId.toString()).toStrictEqual(room.toString());

            const [sas, outgoingVerificationRequest] = await verificationRequest.startSas();

            expect(outgoingVerificationRequest).toBeInstanceOf(RoomMessageRequest);
            expect(outgoingVerificationRequest.id).toBeDefined();
            expect(outgoingVerificationRequest.room_id).toStrictEqual(room.toString());
            expect(outgoingVerificationRequest.txn_id).toBeDefined();
            expect(outgoingVerificationRequest.event_type).toStrictEqual("m.key.verification.start");
            expect(outgoingVerificationRequest.body).toBeDefined();

            const body = JSON.parse(outgoingVerificationRequest.body);
            expect(body).toMatchObject({
                "from_device": expect.any(String),
                "method": "m.sas.v1",
                "key_agreement_protocols": [expect.any(String)],
                "hashes": [expect.any(String)],
                "message_authentication_codes": [expect.any(String), expect.any(String), expect.any(String)],
                "short_authentication_string": ["decimal", "emoji"],
                "m.relates_to": {
                    rel_type: "m.reference",
                    event_id: eventId.toString(),
                },
            });

            const outgoingCancellationRequest = sas.cancelWithCode("org.matrix.custom");

            const cancellationBody = JSON.parse(outgoingCancellationRequest.body);
            expect(cancellationBody.code).toEqual("org.matrix.custom");

            let cancelInfo = verificationRequest.cancelInfo;
            expect(cancelInfo).toBeTruthy();
            expect(cancelInfo.cancelCode()).toEqual("org.matrix.custom");
            expect(cancelInfo.cancelledbyUs()).toBe(true);
        });

        test("can handle a cancelled in-room verification", async () => {
            let _ = m.bootstrapCrossSigning(true);
            const identity = await m.getIdentity(new UserId("@example:morpheus.localhost"));

            const eventId = new EventId("$qnc-F-dvnEYJTyHq_iKxU2bZ1CI92-kuZq3a5lr5ZRg");
            const verificationRequest = await identity.requestVerification(room, eventId);

            await m.receiveVerificationEvent(
                JSON.stringify({
                    sender: "@example:morpheus.localhost",
                    type: "m.key.verification.cancel",
                    event_id: "$gQWuamMe6taH7oaEX6DHnIrvn8kden7vt9a9e2xBzl0",
                    origin_server_ts: 1674037264827,
                    content: {
                        "reason": "Cancelled by user",
                        "code": "m.user",
                        "m.relates_to": {
                            rel_type: "m.reference",
                            event_id: eventId.toString(),
                        },
                    },
                }),
                room,
            );

            let cancelInfo = verificationRequest.cancelInfo;
            expect(cancelInfo).toBeTruthy();
            expect(cancelInfo.cancelCode()).toEqual("m.user");
            expect(cancelInfo.cancelledbyUs()).toBe(false);
        });
    });

    describe("verifyBackup", () => {
        test("rejects backups with unknown signature", async () => {
            let m = await machine();

            let backupData = {
                version: "2",
                algorithm: "m.megolm_backup.v1.curve25519-aes-sha2",
                auth_data: {
                    public_key: "ddIQtIjfCzfR69I/imE7XiGsPPKA1KF74aclXsiWh08",
                    signatures: {
                        "@web:example.org": {
                            "ed25519:WVJSAIOBUZ":
                                "zzqyWl3ek5dSWKKeNPrpMFDQyu9ZlHrA2XpAaXtcSyo8BoZIu0K2flfT+N0YgVee2gmAZdLAribwgoCopvTeAg",
                            "ed25519:LHMKRoMYl7haWnst5Xo54DuRqjZ5h/Sk1lxc4heSEcI":
                                "YwRj5UqKrbMbAb/VK0Dwj4HspiOjSN64cM5SwFQ7HEcFiHp4gJmHtV90kl+12OLiE5JqRWvgzsx61hSXM/JDCA",
                        },
                    },
                },
                etag: "0",
                count: 0,
            };

            const state = await m.verifyBackup(backupData);

            expect(state.deviceState).toStrictEqual(SignatureState.Missing);
            expect(state.userState).toStrictEqual(SignatureState.Missing);
        });

        test("accepts own signatures", async () => {
            let m = await machine();
            let _ = m.bootstrapCrossSigning(true);

            let keyBackupKey = BackupDecryptionKey.createRandomKey();

            let authData = {
                public_key: keyBackupKey.megolmV1PublicKey.publicKeyBase64,
            };

            let canonical = JSON.stringify(authData);

            let signaturesJSON = (await m.sign(canonical)).asJSON();

            let backupData = {
                algorithm: keyBackupKey.megolmV1PublicKey.algorithm,
                auth_data: {
                    signatures: JSON.parse(signaturesJSON),
                    ...authData,
                },
            };

            const state = await m.verifyBackup(backupData);

            expect(state.deviceState).toStrictEqual(SignatureState.ValidAndTrusted);
            expect(state.userState).toStrictEqual(SignatureState.ValidAndTrusted);
        });
    });

    describe("key backup", () => {
        test("correctly backs up keys", async () => {
            let m = await machine();

            await m.shareRoomKey(room, [new UserId("@bob:example.org")], new EncryptionSettings());

            let counts = await m.roomKeyCounts();

            expect(counts.total).toStrictEqual(1);
            expect(counts.backedUp).toStrictEqual(0);

            let backupEnabled = await m.isBackupEnabled();
            expect(backupEnabled).toStrictEqual(false);

            let keyBackupKey = BackupDecryptionKey.createRandomKey();

            await m.enableBackupV1(keyBackupKey.megolmV1PublicKey.publicKeyBase64, "1");

            expect(await m.isBackupEnabled()).toStrictEqual(true);

            let outgoing = (await m.backupRoomKeys())!;

            expect(outgoing.id).toBeDefined();
            expect(outgoing.body).toBeDefined();
            expect(outgoing.type).toStrictEqual(RequestType.KeysBackup);

            let exportedKey = JSON.parse(outgoing.body);

            let sessions = exportedKey.rooms["!baz:matrix.org"].sessions;
            // @ts-ignore "object is of type 'unknown'"
            let sessionData = Object.values(sessions)[0].session_data;

            // should decrypt with the created key
            let decrypted = JSON.parse(
                keyBackupKey.decryptV1(sessionData.ephemeral, sessionData.mac, sessionData.ciphertext),
            );
            expect(decrypted.algorithm).toStrictEqual("m.megolm.v1.aes-sha2");

            // simulate key backed up
            await m.markRequestAsSent(outgoing.id, outgoing.type, '{"etag":"1","count":3}');

            let newCounts = await m.roomKeyCounts();

            expect(newCounts.total).toStrictEqual(1);
            expect(newCounts.backedUp).toStrictEqual(1);
        });

        test("can save and get private key", async () => {
            let m = await machine();

            let keyBackupKey = BackupDecryptionKey.createRandomKey();

            await m.saveBackupDecryptionKey(keyBackupKey, "3");

            let savedKey = await m.getBackupKeys();

            expect(savedKey.decryptionKey?.toBase64()).toStrictEqual(keyBackupKey.toBase64());
            expect(savedKey.decryptionKeyBase64).toStrictEqual(keyBackupKey.toBase64());
            expect(savedKey.backupVersion).toStrictEqual("3");
        });

        test("can import keys via importBackedUpRoomKeys", async () => {
            // first do a backup from one OlmMachine
            const m = await machine();
            await m.shareRoomKey(room, [new UserId("@bob:example.org")], new EncryptionSettings());
            const keyBackupKey = BackupDecryptionKey.createRandomKey();
            await m.enableBackupV1(keyBackupKey.megolmV1PublicKey.publicKeyBase64, "1");
            const outgoing = (await m.backupRoomKeys())!;
            expect(outgoing.type).toStrictEqual(RequestType.KeysBackup);

            // Map from room ID, to map from session ID to the backup data.
            const exportedKeys = JSON.parse(outgoing.body) as {
                rooms: Record<string, { sessions: Record<string, any> }>;
            };

            // decrypt the backup
            const decryptedKeyMap = new Map();
            for (const [roomId, roomKeys] of Object.entries(exportedKeys.rooms)) {
                const decryptedRoomKeyMap = new Map();
                decryptedKeyMap.set(new RoomId(roomId), decryptedRoomKeyMap);
                for (const [sessionId, keyBackupData] of Object.entries(roomKeys.sessions)) {
                    const decrypted = JSON.parse(
                        keyBackupKey.decryptV1(
                            keyBackupData.session_data.ephemeral,
                            keyBackupData.session_data.mac,
                            keyBackupData.session_data.ciphertext,
                        ),
                    );
                    expect(decrypted.algorithm).toStrictEqual("m.megolm.v1.aes-sha2");
                    decryptedRoomKeyMap.set(sessionId, decrypted);
                }
                // and add a bad key
                decryptedRoomKeyMap.set("invalid", {});
            }

            // now import the backup into a new OlmMachine
            const progressListener = jest.fn();
            const m2 = await machine();
            await m2.saveBackupDecryptionKey(keyBackupKey, "1");
            const result = await m2.importBackedUpRoomKeys(decryptedKeyMap, progressListener, "1");
            expect(result.importedCount).toStrictEqual(1);
            expect(result.totalCount).toStrictEqual(1);
            expect(result.keys()).toMatchObject(
                new Map([[room.toString(), new Map([[expect.any(String), new Set([expect.any(String)])]])]]),
            );

            expect(progressListener).toHaveBeenCalledTimes(1);
            expect(progressListener).toHaveBeenCalledWith(0, 2, 1);
        });
    });

    describe("Request missing secrets", () => {
        /**
         * Creates a hypothetical response to a key query request for an account with a pre-existing device and identity.
         *
         * To be used in tests when you want to create a setup where there is an existing device
         * on the account with cross-signing set up.
         *
         * This will create a valid response to a key query request with all needed signatures.
         *
         * @param userId - The user id
         * @param deviceId - The device id
         *
         * @returns A valid response to a key query request that can be feed in a second login for that account.
         */
        async function getKeyQueryResponseWithExistingDevice(userId: UserId, deviceId: DeviceId): Promise<Object> {
            let initialMachine = await OlmMachine.initialize(userId, deviceId);
            const userIdStr = initialMachine.userId.toString();
            const deviceIdStr = initialMachine.deviceId.toString();

            let deviceKeys;
            let outgoingRequests = await initialMachine.outgoingRequests();
            for (const request of outgoingRequests) {
                if (request instanceof KeysUploadRequest) {
                    deviceKeys = JSON.parse(request.body);
                }
            }
            delete deviceKeys.one_time_keys;
            delete deviceKeys.fallback_keys;

            let bootstrapRequest = await initialMachine.bootstrapCrossSigning(true);

            const crossSigning = JSON.parse(bootstrapRequest.uploadSigningKeysRequest.body);
            const newSignature = JSON.parse(bootstrapRequest.uploadSignaturesRequest.body);

            const allSignatures = {
                [userIdStr]: {
                    ...deviceKeys.device_keys.signatures[userIdStr],
                    ...newSignature[userIdStr][deviceIdStr].signatures[userIdStr],
                },
            };

            deviceKeys.device_keys.signatures = allSignatures;

            return {
                device_keys: {
                    [userIdStr]: {
                        [deviceIdStr]: deviceKeys,
                    },
                },
                ...crossSigning,
            };
        }

        /**
         * This function is designed to work with `getKeyQueryResponseWithExistingDevice` to simulate a scenario where
         * an existing device (and cross-signing identity), is already associated with the account.
         *
         * It will create a new login and process a hypothetical response that includes the existing identity and devices.
         *
         * @param userId - the user id of the account
         * @param deviceId - the id of the new device
         * @param hypotheticalResponse - the response to the key query request generated by `getKeyQueryResponseWithExistingDevice`
         *
         * @returns an olm machine with the new device and the hypothetical response processed.
         */
        async function getSecondMachine(userId: UserId, deviceId: DeviceId, hypotheticalResponse: Object) {
            const secondMachine = await OlmMachine.initialize(userId, deviceId);

            const toDeviceEvents = JSON.stringify([]);
            const changedDevices = new DeviceLists();
            const oneTimeKeyCounts = new Map();
            const unusedFallbackKeys = new Set();

            await secondMachine.receiveSyncChanges(
                toDeviceEvents,
                changedDevices,
                oneTimeKeyCounts,
                unusedFallbackKeys,
            );
            let outgoingRequests = await secondMachine.outgoingRequests();

            const request = outgoingRequests[1];
            expect(request).toBeInstanceOf(KeysQueryRequest);

            await secondMachine.markRequestAsSent(
                request.id!,
                RequestType.KeysQuery,
                JSON.stringify(hypotheticalResponse),
            );

            return secondMachine;
        }

        test("Should request cross-signing keys if missing", async () => {
            const userId = new UserId("@alice:example.org");
            const firstDevice = new DeviceId("ABCDEF");
            const hypotheticalResponse = await getKeyQueryResponseWithExistingDevice(userId, firstDevice);

            const secondDeviceId = new DeviceId("GHIJKL");

            const secondMachine = await getSecondMachine(userId, secondDeviceId, hypotheticalResponse);
            const hasMissingSecrets = await secondMachine.requestMissingSecretsIfNeeded();

            expect(hasMissingSecrets).toStrictEqual(true);

            let outgoingRequests = await secondMachine.outgoingRequests();

            let mskRequested = false;
            let sskRequested = false;
            let uskRequested = false;
            for (const request of outgoingRequests) {
                if (request instanceof ToDeviceRequest) {
                    const parsed = JSON.parse(request.body);
                    const message = parsed.messages[userId.toString()]["*"];
                    if (message && message.action === "request") {
                        if (message.name === "m.cross_signing.master") {
                            mskRequested = true;
                        } else if (message.name === "m.cross_signing.self_signing") {
                            sskRequested = true;
                        } else if (message.name === "m.cross_signing.user_signing") {
                            uskRequested = true;
                        }
                    }
                }
            }

            expect(mskRequested).toStrictEqual(true);
            expect(sskRequested).toStrictEqual(true);
            expect(uskRequested).toStrictEqual(true);
        });

        test("Should not request if there are requests already in flight", async () => {
            const userId = new UserId("@alice:example.org");
            const firstDevice = new DeviceId("ABCDEF");
            const hypotheticalResponse = await getKeyQueryResponseWithExistingDevice(userId, firstDevice);

            const secondDeviceId = new DeviceId("GHIJKL");

            const secondMachine = await getSecondMachine(userId, secondDeviceId, hypotheticalResponse);

            const hasMissingSecrets = await secondMachine.requestMissingSecretsIfNeeded();
            expect(hasMissingSecrets).toStrictEqual(true);

            const hasMissingSecretsSecondTry = await secondMachine.requestMissingSecretsIfNeeded();
            expect(hasMissingSecretsSecondTry).toStrictEqual(false);
        });

        test("Should not request cross signing secrets if known", async () => {
            const userId = new UserId("@alice:example.org");
            const firstDevice = new DeviceId("ABCDEF");

            let initialMachine = await OlmMachine.initialize(userId, firstDevice);
            await initialMachine.bootstrapCrossSigning(true);
            let keyBackupKey = BackupDecryptionKey.createRandomKey();

            await initialMachine.saveBackupDecryptionKey(keyBackupKey, "3");

            const hasMissingSecrets = await initialMachine.requestMissingSecretsIfNeeded();

            expect(hasMissingSecrets).toStrictEqual(false);

            let outgoingRequests: AnyOutgoingRequest[] = await initialMachine.outgoingRequests();

            let toDeviceRequests = outgoingRequests.filter((request) => {
                return request instanceof ToDeviceRequest;
            });
            expect(toDeviceRequests).toHaveLength(0);
        });
    });

    test("Updating devices should call devicesUpdatedCallback", async () => {
        const userId = new UserId("@alice:example.org");
        const deviceId = new DeviceId("ABCDEF");
        const firstMachine = await OlmMachine.initialize(userId, deviceId);

        const callback = jest.fn().mockImplementation(() => Promise.resolve(undefined));
        firstMachine.registerDevicesUpdatedCallback(callback);

        const secondDeviceId = new DeviceId("GHIJKL");
        const secondMachine = await OlmMachine.initialize(userId, secondDeviceId);

        // Fish the KeysUploadRequest out of secondMachine's outgoingRequests.
        let deviceKeys;
        for (const request of await secondMachine.outgoingRequests()) {
            if (request instanceof KeysUploadRequest) {
                deviceKeys = JSON.parse(request.body).device_keys;
            }
        }

        // ... and feed it into firstMachine's KeysQueryRequest
        for (const request of await firstMachine.outgoingRequests()) {
            if (request instanceof KeysQueryRequest) {
                await firstMachine.markRequestAsSent(
                    request.id,
                    request.type,
                    JSON.stringify({
                        device_keys: {
                            "@alice:example.org": {
                                GHIJKL: deviceKeys,
                            },
                        },
                    }),
                );
            }
        }
        expect(callback).toHaveBeenCalledWith(["@alice:example.org"]);
    });

    describe.each(["passphrase", undefined])("Room settings (store passphrase '%s')", (storePassphrase) => {
        let m: OlmMachine;

        beforeEach(async () => {
            m = await OlmMachine.initialize(user, device, "store_prefix", storePassphrase);
        });

        test("Should return undefined for an unknown room", async () => {
            await m.setRoomSettings(new RoomId("!test:room"), new RoomSettings());
            const settings = await m.getRoomSettings(new RoomId("!test1:room"));
            expect(settings).toBe(undefined);
        });

        test("Should store and return room settings", async () => {
            const settings = new RoomSettings();
            settings.algorithm = EncryptionAlgorithm.MegolmV1AesSha2;
            settings.onlyAllowTrustedDevices = true;
            settings.sessionRotationPeriodMs = 10000;
            settings.sessionRotationPeriodMessages = 1234;

            await m.setRoomSettings(new RoomId("!test:room"), settings);

            const loadedSettings = await m.getRoomSettings(new RoomId("!test:room"));
            expect(loadedSettings!.algorithm).toEqual(EncryptionAlgorithm.MegolmV1AesSha2);
            expect(loadedSettings!.onlyAllowTrustedDevices).toBe(true);
            expect(loadedSettings!.sessionRotationPeriodMs).toEqual(10000);
            expect(loadedSettings!.sessionRotationPeriodMessages).toEqual(1234);
        });

        test("Should reject unsupported algorithms", async () => {
            const settings = new RoomSettings();
            settings.algorithm = EncryptionAlgorithm.OlmV1Curve25519AesSha2;
            await expect(m.setRoomSettings(new RoomId("!test:room"), settings)).rejects.toThrow(
                /the new settings are invalid/,
            );
        });

        test("Should reject downgrade attacks", async () => {
            const settings = new RoomSettings();
            settings.algorithm = EncryptionAlgorithm.MegolmV1AesSha2;
            settings.onlyAllowTrustedDevices = true;
            settings.sessionRotationPeriodMs = 100;
            settings.sessionRotationPeriodMessages = 10;
            await m.setRoomSettings(new RoomId("!test:room"), settings);

            // Try to increase the rotation period
            settings.sessionRotationPeriodMs = 1000;
            await expect(m.setRoomSettings(new RoomId("!test:room"), settings)).rejects.toThrow(/downgrade/);

            // Check the old settings persist
            const loadedSettings = await m.getRoomSettings(new RoomId("!test:room"));
            expect(loadedSettings!.algorithm).toEqual(EncryptionAlgorithm.MegolmV1AesSha2);
            expect(loadedSettings!.onlyAllowTrustedDevices).toBe(true);
            expect(loadedSettings!.sessionRotationPeriodMs).toEqual(100);
            expect(loadedSettings!.sessionRotationPeriodMessages).toEqual(10);
        });

        test("Should ignore no-op changes", async () => {
            const settings = new RoomSettings();
            settings.algorithm = EncryptionAlgorithm.MegolmV1AesSha2;
            settings.onlyAllowTrustedDevices = true;
            settings.sessionRotationPeriodMs = 100;
            settings.sessionRotationPeriodMessages = 10;
            await m.setRoomSettings(new RoomId("!test:room"), settings);

            const settings2 = new RoomSettings();
            settings2.algorithm = EncryptionAlgorithm.MegolmV1AesSha2;
            settings2.onlyAllowTrustedDevices = true;
            settings2.sessionRotationPeriodMs = 100;
            settings2.sessionRotationPeriodMessages = 10;
            await m.setRoomSettings(new RoomId("!test:room"), settings2);
        });
    });

    describe("Receiving to device messages", () => {
        test("Should return plain text to device objects as they are received", async () => {
            const m = await machine();

            const someClearEvent = {
                sender: "@alice:example.com",
                type: "custom.type",
                content: {
                    value: "foo",
                },
            };

            let toDeviceEvents = [someClearEvent];

            const receivedToDeviceArray = await m.receiveSyncChanges(
                JSON.stringify(toDeviceEvents),
                new DeviceLists(),
                new Map<string, number>(),
                undefined,
            );
            expect(receivedToDeviceArray.length).toBe(1);
            const processed = receivedToDeviceArray[0];
            expect(processed.type).toEqual(ProcessedToDeviceEventType.PlainText);
            expect(processed).toBeInstanceOf(PlainTextToDeviceEvent);
            const toDeviceEvent = JSON.parse(processed.rawEvent);

            expect(toDeviceEvent.sender).toEqual("@alice:example.com");
            expect(toDeviceEvent.type).toEqual("custom.type");
            expect(toDeviceEvent.content.value).toEqual("foo");
        });

        test("Should return unable to decrypt to device untouched", async () => {
            const m = await machine();

            const aliceCurve = m.identityKeys.curve25519.toBase64();

            const utdEvent = {
                content: {
                    "algorithm": "m.olm.v1.curve25519-aes-sha2",
                    "ciphertext": {
                        [aliceCurve]: {
                            // this payload is just captured from a sync of some other element web with other users
                            body: "Awogjvpx458CGhuo77HX/+tp1sxgRoCi7iAlzMvfrpbWoREQAiKACysX/p+ojr5QitCi9WRXNyamW2v2LTvoyWKtVaA2oHnYGR5s5RYhDfnIgh5MMSqqKlAbfqLvrbLovTYcKagCBbFnbA43f6zYM44buGgy8q70hMVH5WP6aK1E9Z3DVZ+8PnXQGpsrxvz2IsL6w0Nzl/qUyBEQFcgkjoDPawbsZRCllMgq2LQUyqlun6IgDTCozqsfxhDWpdfYGde4z16m34Ang7f5pH+BmPrFs6E1AO5+UbhhhS6NwWlfEtA6/9yfMxWLz1d2OrLh+QG7lYFAU9/CzIoPxaHKKr4JxgL9CjsmUPyDymWOWHP0jLi1NwpOv6hGpx0FgM7jJIMk6gWGgC5rEgEeTIwdrJh3F9OKTNSva5hvD9LomGk6tZgzQG6oap1e3wiOUyTt6S7BlyMppIu3RlIiNihZ9e17JEGiGDXOXzMJ6ISAgvGVgTP7+EvyEt2Wt4du7uBo/UvljRvVNu3I8tfItizPAOlvz460+aBDxk+sflJWt7OnhiyPnOCfopb+1RzqKVCnnPyVaP2f4BPf8qpn/f5YZk+5jJgBrGPiHzzmb3sQ5pC470s6+U3MpVFlFTG/xPBtMRMwPsbKoHfnRPqIqGu5dQ1Sw7T6taDXWjP450TvjxgHK5t2z1rLA2SXzAB1P8xbi6YXqQwxL6PvMNHn/TM0jiIQHYuqg5/RKLyhHybfP8JAjgNBw9z16wfKR/YoYFr7c+S4McQaMNa8v2SxGzhpCC3duAoK2qCWLEkYRO5cMCsGm/9bf8Q+//OykygBU/hdkT1eHUbexgALPLdfhzduutU7pbChg4T7SH7euh/3NLmS/SQvkmPfm3ckbh/Vlcj9CsXws/7MX/VJbhpbyzgBNtMnbG6tAeAofMa6Go/yMgiNBZIhLpAm31iUbUhaGm2IIlF/lsmSYEiBPoSVfFU44tetX2I/PBDGiBlzyU+yC2TOEBwMGxBE3WHbIe5/7sKW8xJF9t+HBfxIyW1QRtY3EKdEcuVOTyMxYzq3L5OKOOtPDHObYiiXg00mAgdQqgfkEAIfoRCOa2NYfTedwwo0S77eQ1sPvW5Hhf+Cm+bLibkWzaYHEZF+vyE9/Tn0tZGtH07RXfUyhp1vtTH49OBZHGkb/r+L8OjYJTST1dDCGqeGXO3uwYjoWHXtezLVHYgL+UOwcLJfMF5s9DQiqcfYXzp2kEWGsaetBFXcUWqq4RMHqlr6QfbxyuYLlQzc/AYA/MrT3J6nDpNLcvozH3RcIs8NcKcjdtjvgL0QGThy3RcecJQEDx3STrkkePL3dlyFCtVsmtQ0vjBBCxUgdySfxiobGGnpezZYi7q+Xz61GOZ9QqYmkcZOPzfNWeqtmzB7gqlH1gkFsK2yMAzKq2XCDFHvA7YAT3yMGiY06FcQ+2jyg7Bk2Q+AvjTG8hlPlmt6BZfW5cz1qx1apQn1qHXHrgfWcI52rApYQlNPOU1Uc8kZ8Ee6XUhhXBGY1rvZiKjKFG0PPuS8xo4/P7/u+gH5gItmEVDFL6giYPFsPpqAQkUN7hFoGiVZEjO4PwrLOmydsEcNOfACqrnUs08FQtvPg0sjHnxh6nh6FUQv93ukKl6+c9d+pCsN2xukrQ7Dog3nrjFZ6PrS5J0k9rDAOwTB55sfGXPZ2rATOK1WS4XcpsCtqwnYm4sGNc8ALMQkQ97zCnw8TcQwLvdUMlfbqQ5ykDQpQD68fITEDDHmBAeTCjpC713E6AhvOMwTJvjhd7hSkeOTRTmn9zXIVGNo1jSr8u0xO9uLGeWsV0+UlRLgp7/nsgfermjwNN8wj6MW3DHGS8UzzYfe9TGCeywqqIUTqgfXY48leGgB7twh4cl4jcOQniLATTvigIAQIvq/Uv8L45BGnkpKTdQ5F73gehXdVA",
                            type: 1,
                        },
                    },
                    "org.matrix.msgid": "93ee0170aa7740d0ac9ee137e820302d",
                    "sender_key": "WJ6Ce7U67a6jqkHYHd8o0+5H4bqdi9hInZdk0+swuXs",
                },
                type: "m.room.encrypted",
                sender: "@bob:example.org",
            };

            let toDeviceEvents = [utdEvent];

            const receivedToDeviceArray = await m.receiveSyncChanges(
                JSON.stringify(toDeviceEvents),
                new DeviceLists(),
                new Map<string, number>(),
                undefined,
            );
            expect(receivedToDeviceArray.length).toBe(1);
            const processed = receivedToDeviceArray[0];
            expect(processed.type).toEqual(ProcessedToDeviceEventType.UnableToDecrypt);
            expect(processed).toBeInstanceOf(UTDToDeviceEvent);
            const toDeviceEvent = JSON.parse(processed.rawEvent);

            expect(toDeviceEvent.sender).toEqual("@bob:example.org");
            expect(toDeviceEvent.type).toEqual("m.room.encrypted");
            expect(toDeviceEvent.content.ciphertext).toBeDefined();
        });

        test("Should return invalid event properly", async () => {
            const m = await machine();

            let eventWithNoType = {
                sender: "@alice:example.com",
                content: {
                    algorithm: "m.megolm.v1.aes-sha2",
                    code: "m.unverified",
                    reason: "Device not verified",
                    room_id: "!Cuyf34gef24t:localhost",
                    sender_key: "RF3s+E7RkTQTGF2d8Deol0FkQvgII2aJDf3/Jp5mxVU",
                    session_id: "X3lUlvLELLYxeTx4yOVu6UDpasGEVO0Jbu+QFnm0cKQ",
                },
            };

            const eventWithMalformedCurveKey = {
                content: {
                    "algorithm": "m.olm.v1.curve25519-aes-sha2",
                    "ciphertext": {
                        INVALID_CURVE: {
                            // this payload is just captured from a sync of some other element web with other users
                            body: "Awogjvpx458CGhuo77HX/",
                            type: 1,
                        },
                    },
                    "org.matrix.msgid": "93ee0170aa7740d0ac9ee137e820302d",
                    "sender_key": "WJ6Ce7U67a6jqkHYHd8o0+5H4bqdi9hInZdk0+swuXs",
                },
                type: "m.room.encrypted",
                sender: "@bob:example.org",
            };

            let toDeviceEvents = [eventWithNoType, eventWithMalformedCurveKey];

            const receivedToDeviceArray = await m.receiveSyncChanges(
                JSON.stringify(toDeviceEvents),
                new DeviceLists(),
                new Map<string, number>(),
                undefined,
            );

            expect(receivedToDeviceArray.length).toBe(2);

            const processed0 = receivedToDeviceArray[0];
            expect(processed0.type).toEqual(ProcessedToDeviceEventType.Invalid);
            expect(processed0).toBeInstanceOf(InvalidToDeviceEvent);
            const toDeviceEvent0 = JSON.parse(processed0.rawEvent);
            expect(toDeviceEvent0.sender).toEqual("@alice:example.com");
            expect(toDeviceEvent0.content).toBeDefined();
            expect(toDeviceEvent0.type).toBeUndefined();

            const processed1 = receivedToDeviceArray[1];
            expect(processed1.type).toEqual(ProcessedToDeviceEventType.Invalid);
            const toDeviceEvent1 = JSON.parse(processed1.rawEvent);
            expect(toDeviceEvent1.sender).toEqual("@bob:example.org");
            expect(toDeviceEvent1.type).toEqual("m.room.encrypted");
        });

        test("Should return the clear text version of decrypted events", async () => {
            const aliceUserId = new UserId("@alice:example.org");
            const aliceDeviceId = new DeviceId("ALICE_DEV");

            const bobUserId = new UserId("@bob:example.org");
            const bobDeviceId = new DeviceId("BOB_DEV");

            const alice = await machine(aliceUserId, aliceDeviceId);
            const bob = await machine(bobUserId, bobDeviceId);

            const [keysUploadRequest, keysQueryRequest] = await bob.outgoingRequests();
            expect(keysUploadRequest).toBeInstanceOf(KeysUploadRequest);
            expect(keysQueryRequest).toBeInstanceOf(KeysQueryRequest);
            const keysUploadBody = JSON.parse(keysUploadRequest.body);
            const otks = Object.values(keysUploadBody.one_time_keys);
            await bob.markRequestAsSent(
                keysUploadRequest.id!,
                keysUploadRequest.type,
                JSON.stringify({
                    one_time_key_counts: {
                        signed_curve25519: otks.length,
                    },
                }),
            );

            // Let Alice know about bob keys
            await alice.markRequestAsSent(
                "SomeUniqueId",
                RequestType.KeysQuery,
                JSON.stringify({
                    device_keys: {
                        "@bob:example.org": {
                            BOB_DEV: keysUploadBody.device_keys,
                        },
                    },
                    failures: {},
                }),
            );

            // Let Alice claim one otk for bob to establish the olm session
            const [otkId, otk] = Object.entries(keysUploadBody.one_time_keys)[0];
            await alice.markRequestAsSent(
                "foo",
                RequestType.KeysClaim,
                JSON.stringify({
                    one_time_keys: {
                        "@bob:example.org": {
                            BOB_DEV: {
                                [otkId]: otk,
                            },
                        },
                    },
                }),
            );

            {
                // Let bob be aware of alice device
                // If not olm decryption will fail because of MissingSigningKeys
                const [keysUploadRequest, keysQueryRequest] = await alice.outgoingRequests();
                const keysUploadBody = JSON.parse(keysUploadRequest.body);
                await bob.markRequestAsSent(
                    "SomeUniqueId",
                    RequestType.KeysQuery,
                    JSON.stringify({
                        device_keys: {
                            "@alice:example.org": {
                                ALICE_DEV: keysUploadBody.device_keys,
                            },
                        },
                        failures: {},
                    }),
                );
            }

            const aliceBobDevice = (await alice.getDevice(bobUserId, bobDeviceId))!;
            const encryptedContent = await aliceBobDevice.encryptToDeviceEvent("custom.type", {
                foo: "bar",
            });

            const encryptedToDevice = {
                type: "m.room.encrypted",
                content: JSON.parse(encryptedContent),
                sender: "@alice:example.org",
            };

            // Bob should be able to decrypt this

            const receivedToDeviceArray = await bob.receiveSyncChanges(
                JSON.stringify([encryptedToDevice]),
                new DeviceLists(),
                new Map<string, number>(),
                undefined,
            );
            expect(receivedToDeviceArray.length).toBe(1);
            const processed = receivedToDeviceArray[0];
            expect(processed.type).toEqual(ProcessedToDeviceEventType.Decrypted);
            expect(processed).toBeInstanceOf(DecryptedToDeviceEvent);
            const toDeviceEvent = JSON.parse(processed.rawEvent);

            expect(toDeviceEvent.sender).toEqual("@alice:example.org");
            expect(toDeviceEvent.type).toEqual("custom.type");
            expect(toDeviceEvent.content.foo).toEqual("bar");

            const encryptionInfo = (processed as DecryptedToDeviceEvent).encryptionInfo;
            expect(encryptionInfo.senderCurve25519Key).toEqual(alice.identityKeys.curve25519.toBase64());
            expect(encryptionInfo.isSenderVerified()).toBe(false);
        });

        test("Should refuse to decrypt from senders that are not sufficiently trusted", async () => {
            const aliceUserId = new UserId("@alice:example.org");
            const aliceDeviceId = new DeviceId("ALICE_DEV");

            const bobUserId = new UserId("@bob:example.org");
            const bobDeviceId = new DeviceId("BOB_DEV");

            const alice = await machine(aliceUserId, aliceDeviceId);
            const bob = await machine(bobUserId, bobDeviceId);

            const [keysUploadRequest, keysQueryRequest] = await bob.outgoingRequests();
            expect(keysUploadRequest).toBeInstanceOf(KeysUploadRequest);
            expect(keysQueryRequest).toBeInstanceOf(KeysQueryRequest);
            const keysUploadBody = JSON.parse(keysUploadRequest.body);
            const otks = Object.values(keysUploadBody.one_time_keys);
            await bob.markRequestAsSent(
                keysUploadRequest.id!,
                keysUploadRequest.type,
                JSON.stringify({
                    one_time_key_counts: {
                        signed_curve25519: otks.length,
                    },
                }),
            );

            // Let Alice know about bob keys
            await alice.markRequestAsSent(
                "SomeUniqueId",
                RequestType.KeysQuery,
                JSON.stringify({
                    device_keys: {
                        "@bob:example.org": {
                            BOB_DEV: keysUploadBody.device_keys,
                        },
                    },
                    failures: {},
                }),
            );

            // Let Alice claim one otk for bob to establish the olm session
            const [otkId, otk] = Object.entries(keysUploadBody.one_time_keys)[0];
            await alice.markRequestAsSent(
                "foo",
                RequestType.KeysClaim,
                JSON.stringify({
                    one_time_keys: {
                        "@bob:example.org": {
                            BOB_DEV: {
                                [otkId]: otk,
                            },
                        },
                    },
                }),
            );

            {
                // Let bob be aware of alice device
                // If not olm decryption will fail because of MissingSigningKeys
                const [keysUploadRequest, keysQueryRequest] = await alice.outgoingRequests();
                const keysUploadBody = JSON.parse(keysUploadRequest.body);
                await bob.markRequestAsSent(
                    "SomeUniqueId",
                    RequestType.KeysQuery,
                    JSON.stringify({
                        device_keys: {
                            "@alice:example.org": {
                                ALICE_DEV: keysUploadBody.device_keys,
                            },
                        },
                        failures: {},
                    }),
                );
            }

            const aliceBobDevice = (await alice.getDevice(bobUserId, bobDeviceId))!;
            const encryptedContent = await aliceBobDevice.encryptToDeviceEvent("custom.type", {
                foo: "bar",
            });

            const encryptedToDevice = {
                type: "m.room.encrypted",
                content: JSON.parse(encryptedContent),
                sender: "@alice:example.org",
            };

            // Bob should be able to decrypt this

            const receivedToDeviceArray = await bob.receiveSyncChanges(
                JSON.stringify([encryptedToDevice]),
                new DeviceLists(),
                new Map<string, number>(),
                undefined,
                new DecryptionSettings(TrustRequirement.CrossSigned),
            );
            expect(receivedToDeviceArray.length).toBe(1);
            const processed = receivedToDeviceArray[0];
            expect(processed.type).toEqual(ProcessedToDeviceEventType.UnableToDecrypt);
            expect(processed).toBeInstanceOf(UTDToDeviceEvent);
        });
    });
});
