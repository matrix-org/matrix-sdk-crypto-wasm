import {
    DehydratedDeviceKey,
    DecryptionSettings,
    DeviceId,
    DeviceLists,
    EncryptionSettings,
    KeysQueryRequest,
    KeysUploadRequest,
    OlmMachine,
    RequestType,
    RoomId,
    TrustRequirement,
    UserId,
} from "@matrix-org/matrix-sdk-crypto-wasm";
import "fake-indexeddb/auto";

afterEach(() => {
    // reset fake-indexeddb after each test, to make sure we don't leak data
    // cf https://github.com/dumbmatter/fakeIndexedDB#wipingresetting-the-indexeddb-for-a-fresh-state
    // eslint-disable-next-line no-global-assign
    indexedDB = new IDBFactory();
});

describe("dehydrated devices", () => {
    test("can save and restore dehydrated device pickle key", async () => {
        const user = new UserId("@alice:example.org");
        // set up OlmMachine to dehydrated device
        const machine = await OlmMachine.initialize(user, new DeviceId("ABCDEFG"));

        const dehydratedDevices = machine.dehydratedDevices();
        const key = DehydratedDeviceKey.createRandomKey();

        await dehydratedDevices.saveDehydratedDeviceKey(key);

        const loaded_key = await dehydratedDevices.getDehydratedDeviceKey();

        expect(key.toBase64()).toEqual(loaded_key!.toBase64());
    });

    test("can delete a previously saved dehydrated device key", async () => {
        const user = new UserId("@alice:example.org");
        // set up OlmMachine to dehydrated device
        const machine = await OlmMachine.initialize(user, new DeviceId("ABCDEFG"));
        const dehydratedDevices = machine.dehydratedDevices();

        const key = DehydratedDeviceKey.createRandomKey();

        await dehydratedDevices.saveDehydratedDeviceKey(key);

        const loaded_key = await dehydratedDevices.getDehydratedDeviceKey();

        expect(loaded_key).toBeDefined();

        await dehydratedDevices.deleteDehydratedDeviceKey();

        const loaded_key_after = await dehydratedDevices.getDehydratedDeviceKey();
        expect(loaded_key_after).toBeUndefined();
    });

    test("can dehydrate and rehydrate a device", async () => {
        const room = new RoomId("!test:localhost");
        const user = new UserId("@alice:example.org");

        // set up OlmMachine to dehydrated device
        const machine = await OlmMachine.initialize(user, new DeviceId("ABCDEFG"));
        await machine.bootstrapCrossSigning(true);
        machine.receiveSyncChanges(
            JSON.stringify([]), // to-device events
            new DeviceLists(),
            new Map(), // otk counts
            new Set(), // unused fallback keys
        );
        const [keysUploadRequest, keysQueryRequest] = await machine.outgoingRequests();
        expect(keysUploadRequest).toBeInstanceOf(KeysUploadRequest);
        expect(keysQueryRequest).toBeInstanceOf(KeysQueryRequest);
        const keysUploadBody = JSON.parse(keysUploadRequest.body);
        const otks = Object.values(keysUploadBody.one_time_keys);
        await machine.markRequestAsSent(
            keysUploadRequest.id!,
            keysUploadRequest.type,
            JSON.stringify({
                one_time_key_counts: {
                    signed_curve25519: otks.length,
                },
            }),
        );

        // create dehydrated device
        const dehydratedDevices = machine.dehydratedDevices();
        const device = await dehydratedDevices.create();

        const key = DehydratedDeviceKey.createKeyFromArray(new Uint8Array(32));
        const dehydrationRequest = await device.keysForUpload("Dehydrated device", key);
        const dehydrationBody = JSON.parse(dehydrationRequest.body);

        // let the machine know about the dehydrated device's device keys and OTK
        await machine.markRequestAsSent(
            keysQueryRequest.id!,
            keysQueryRequest.type,
            JSON.stringify({
                device_keys: {
                    "@alice:example.org": {
                        ABCDEFG: keysUploadBody.device_keys,
                        [dehydrationBody.device_id]: dehydrationBody.device_keys,
                    },
                },
                failures: {},
            }),
        );

        const [dehydratedOtkId, dehydratedOtk] = Object.entries(dehydrationBody.one_time_keys)[0];
        await machine.markRequestAsSent(
            "foo",
            RequestType.KeysClaim,
            JSON.stringify({
                one_time_keys: {
                    "@alice:example.org": {
                        [dehydrationBody.device_id]: {
                            [dehydratedOtkId]: dehydratedOtk,
                        },
                    },
                },
            }),
        );

        // encrypt an event and send key to dehydrated device
        const [keyShareRequest] = await machine.shareRoomKey(room, [user.clone()], new EncryptionSettings());
        const keyShareContent = JSON.parse(keyShareRequest.body).messages["@alice:example.org"][
            dehydrationBody.device_id
        ];

        const encryptedMessage = await machine.encryptRoomEvent(
            room,
            "m.room.message",
            JSON.stringify({
                msgtype: "m.text",
                body: "Hello, World!",
            }),
        );

        // create new OlmMachine to rehydrate the device
        const machine2 = await OlmMachine.initialize(user, new DeviceId("HIJKLMN"));
        const dehydratedDevices2 = machine2.dehydratedDevices();
        const rehydratedDevice = await dehydratedDevices2.rehydrate(
            key,
            new DeviceId(dehydrationBody.device_id),
            JSON.stringify(dehydrationBody.device_data),
        );

        // process the room key sent from the first machine
        await rehydratedDevice.receiveEvents(
            JSON.stringify([
                {
                    type: "m.room.encrypted",
                    sender: "@alice:example.org",
                    content: keyShareContent,
                },
            ]),
        );

        // decrypt the event sent by the first machine
        const encryptedEvent = JSON.stringify({
            type: "m.room.encrypted",
            event_id: "$event_id:example.org",
            origin_server_ts: Date.now(),
            sender: "@alice:example.org",
            content: JSON.parse(encryptedMessage),
            unsigned: {
                age: 0,
            },
        });

        const decryptionSettings = new DecryptionSettings(TrustRequirement.Untrusted);
        const decrypted = await machine2.decryptRoomEvent(encryptedEvent, room, decryptionSettings);
        const decryptedEvent = JSON.parse(decrypted.event);
        expect(decryptedEvent.content.body).toStrictEqual("Hello, World!");
    });
});
