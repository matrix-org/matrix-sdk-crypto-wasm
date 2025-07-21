/*
Copyright 2025 The Matrix.org Foundation C.I.C.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

import {
    Attachment,
    CollectStrategy,
    DecryptionSettings,
    DeviceId,
    EncryptionSettings,
    OlmMachine,
    RoomId,
    ToDeviceRequest,
    TrustRequirement,
    UserId,
} from "@matrix-org/matrix-sdk-crypto-wasm";
import { addMachineToMachine, encryptEvent, establishOlmSession, forwardToDeviceMessage } from "./helper.ts";

import "fake-indexeddb/auto";

const room = new RoomId("!test:localhost");
const otherUser = new UserId("@example:localhost");
const otherUserDeviceId = new DeviceId("B");

afterEach(() => {
    // reset fake-indexeddb after each test, to make sure we don't leak data
    // cf https://github.com/dumbmatter/fakeIndexedDB#wipingresetting-the-indexeddb-for-a-fresh-state
    // eslint-disable-next-line no-global-assign
    indexedDB = new IDBFactory();
});

describe("encrypted history sharing/decrypting", () => {
    let senderMachine: OlmMachine;
    let receiverMachine: OlmMachine;

    beforeEach(async () => {
        // We need two devices, both cross-signed, where each knows about the other.
        senderMachine = await OlmMachine.initialize(new UserId("@alice:example.org"), new DeviceId("A"));
        receiverMachine = await OlmMachine.initialize(otherUser, otherUserDeviceId);
        await addMachineToMachine(receiverMachine, senderMachine);
        await addMachineToMachine(senderMachine, receiverMachine);
    });

    describe("buildRoomKeyBundle", () => {
        test("returns `undefined` if there are no keys", async () => {
            const bundle = await senderMachine.buildRoomKeyBundle(room);
            expect(bundle).toBe(undefined);
        });

        test("creates a key bundle", async () => {
            // Create the megolm session
            await senderMachine.shareRoomKey(room, [], new EncryptionSettings());

            // Now build the bundle, which should include the session.
            const bundle = await senderMachine.buildRoomKeyBundle(room);
            expect(bundle).toBeDefined();
            const decryptedBundle = JSON.parse(new TextDecoder().decode(Attachment.decrypt(bundle!)));

            expect(decryptedBundle.withheld).toEqual([]);
            expect(decryptedBundle.room_keys).toHaveLength(1);
            expect(decryptedBundle.room_keys[0].room_id).toEqual(room.toString());
            expect(decryptedBundle.room_keys[0].sender_claimed_keys).toEqual({
                ed25519: senderMachine.identityKeys.ed25519.toBase64(),
            });
            expect(decryptedBundle.room_keys[0].sender_key).toEqual(senderMachine.identityKeys.curve25519.toBase64());
        });
    });

    describe("shareKeyBundle", () => {
        test("returns to-device messages", async () => {
            // Create the megolm session and build a bundle so that we have something to share
            await senderMachine.shareRoomKey(room, [], new EncryptionSettings());
            const bundle = await senderMachine.buildRoomKeyBundle(room);

            // Now initiate the share request
            const request = await shareRoomKeyBundleData(senderMachine, receiverMachine, bundle!.mediaEncryptionInfo);

            expect(request.event_type).toEqual("m.room.encrypted");
            const requestBody = JSON.parse(request.body);
            expect(requestBody.messages[otherUser.toString()][otherUserDeviceId.toString()]).toBeDefined();
        });
    });

    describe("getReceivedRoomKeyBundleData", () => {
        test("returns details about received room key bundles", async () => {
            // Create the megolm session and build a bundle so that we have something to share
            await senderMachine.shareRoomKey(room, [], new EncryptionSettings());
            const bundle = await senderMachine.buildRoomKeyBundle(room);

            // Share the bundle details with the recipient
            const request = await shareRoomKeyBundleData(senderMachine, receiverMachine, bundle!.mediaEncryptionInfo);
            await forwardToDeviceMessage(senderMachine.userId, receiverMachine, request);

            // The recipient should now know about the details of the bundle.
            const data = await receiverMachine.getReceivedRoomKeyBundleData(room, senderMachine.userId);
            expect(data).toBeDefined();
            expect(data!.senderUser.toString()).toEqual(senderMachine.userId.toString());
            expect(data!.url).toEqual("mxc://test/test");
            expect(data!.encryptionInfo).toEqual(bundle!.mediaEncryptionInfo);
        });
    });

    describe("receiveRoomKeyBundle", () => {
        test("imports room keys", async () => {
            // Create the megolm session and send a message that the recipient should be able to decrypt in the end.
            await senderMachine.shareRoomKey(room, [], new EncryptionSettings());
            const encryptedEvent = await encryptEvent(senderMachine, room, "m.room.message", '{ "body": "Hi!" }');

            // Build the bundle, and share details with the recipient
            const bundle = await senderMachine.buildRoomKeyBundle(room);

            // Share the bundle details with the recipient
            const request = await shareRoomKeyBundleData(senderMachine, receiverMachine, bundle!.mediaEncryptionInfo);
            await forwardToDeviceMessage(senderMachine.userId, receiverMachine, request);

            // The recipient should now know about the details of the bundle.
            const receivedBundleData = await receiverMachine.getReceivedRoomKeyBundleData(room, senderMachine.userId);
            expect(receivedBundleData).toBeDefined();

            // ... and receives the bundle itself.
            await receiverMachine.receiveRoomKeyBundle(receivedBundleData!, bundle!.encryptedData);

            // The recipient should now be able to decrypt the encrypted event.
            const decryptionSettings = new DecryptionSettings(TrustRequirement.Untrusted);
            const decryptedData = await receiverMachine.decryptRoomEvent(encryptedEvent, room, decryptionSettings);
            const decryptedEvent = JSON.parse(decryptedData.event);
            expect(decryptedEvent.content.body).toEqual("Hi!");
        });
    });
});

/** Make a to-device request for sharing a room key bundle from senderMachine to receiverMachine. */
async function shareRoomKeyBundleData(
    senderMachine: OlmMachine,
    receiverMachine: OlmMachine,
    mediaEncryptionInfo?: string,
): Promise<ToDeviceRequest> {
    await establishOlmSession(senderMachine, receiverMachine);

    const requests = await senderMachine.shareRoomKeyBundleData(
        receiverMachine.userId,
        room,
        "mxc://test/test",
        mediaEncryptionInfo,
        CollectStrategy.identityBasedStrategy(),
    );

    expect(requests).toHaveLength(1);
    return requests[0];
}
