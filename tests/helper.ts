/*
Copyright 2022-2025 The Matrix.org Foundation C.I.C.

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
    DeviceLists,
    KeysQueryRequest,
    KeysUploadRequest,
    OlmMachine,
    RequestType,
    RoomId,
    ToDeviceRequest,
    UserId,
} from "@matrix-org/matrix-sdk-crypto-wasm";

export function* zip(...arrays: Array<Array<any>>): Generator<any> {
    const len = Math.min(...arrays.map((array) => array.length));

    for (let nth = 0; nth < len; ++nth) {
        yield [...arrays.map((array) => array.at(nth))];
    }
}

// Add a machine to another machine, i.e. be sure a machine knows
// another exists.
export async function addMachineToMachine(machineToAdd: OlmMachine, machine: OlmMachine): Promise<void> {
    const toDeviceEvents = JSON.stringify([]);
    const changedDevices = new DeviceLists();
    const oneTimeKeyCounts = new Map();
    const unusedFallbackKeys = new Set();

    const receiveSyncChanges = await machineToAdd.receiveSyncChanges(
        toDeviceEvents,
        changedDevices,
        oneTimeKeyCounts,
        unusedFallbackKeys,
    );
    expect(receiveSyncChanges).toEqual([]);

    const outgoingRequests = await machineToAdd.outgoingRequests();

    expect(outgoingRequests).toHaveLength(2);

    let keysUploadRequest;

    // Read the `KeysUploadRequest`.
    {
        expect(outgoingRequests[0]).toBeInstanceOf(KeysUploadRequest);
        keysUploadRequest = outgoingRequests[0] as KeysUploadRequest;

        expect(outgoingRequests[0].id).toBeDefined();
        expect(outgoingRequests[0].type).toStrictEqual(RequestType.KeysUpload);
        expect(outgoingRequests[0].body).toBeDefined();

        const body = JSON.parse(outgoingRequests[0].body);
        expect(body.device_keys).toBeDefined();
        expect(body.one_time_keys).toBeDefined();

        // https://spec.matrix.org/v1.2/client-server-api/#post_matrixclientv3keysupload
        const hypotheticalResponse = JSON.stringify({
            one_time_key_counts: {
                curve25519: 10,
                signed_curve25519: 20,
            },
        });
        const marked = await machineToAdd.markRequestAsSent(
            keysUploadRequest.id,
            outgoingRequests[0].type,
            hypotheticalResponse,
        );
        expect(marked).toStrictEqual(true);
    }

    {
        expect(outgoingRequests[1]).toBeInstanceOf(KeysQueryRequest);
        let keysQueryRequest = outgoingRequests[1] as KeysQueryRequest;

        let bootstrapCrossSigningResult = await machineToAdd.bootstrapCrossSigning(true);
        let signingKeysUploadRequest = bootstrapCrossSigningResult.uploadSigningKeysRequest;
        const uploadSignaturesRequestBody = JSON.parse(bootstrapCrossSigningResult.uploadSignaturesRequest.body);

        // Let's forge a `KeysQuery`'s response.
        let keyQueryResponse = {
            device_keys: {} as Record<string, any>,
            master_keys: {} as Record<string, any>,
            self_signing_keys: {} as Record<string, any>,
            user_signing_keys: {} as Record<string, any>,
        };
        const userId = machineToAdd.userId.toString();
        const deviceId = machineToAdd.deviceId.toString();
        keyQueryResponse.device_keys[userId] = {};
        keyQueryResponse.device_keys[userId][deviceId] = JSON.parse(keysUploadRequest.body).device_keys;

        // Hack in the cross-signing signature on the device from `bootstrapCrossSigning`
        expect(uploadSignaturesRequestBody[userId][deviceId]).toBeDefined();
        Object.assign(
            keyQueryResponse.device_keys[userId][deviceId].signatures[userId],
            uploadSignaturesRequestBody[userId][deviceId].signatures[userId],
        );

        const keys = JSON.parse(signingKeysUploadRequest.body);
        keyQueryResponse.master_keys[userId] = keys.master_key;
        keyQueryResponse.self_signing_keys[userId] = keys.self_signing_key;
        keyQueryResponse.user_signing_keys[userId] = keys.user_signing_key;

        const marked = await machine.markRequestAsSent(
            keysQueryRequest.id,
            keysQueryRequest.type,
            JSON.stringify(keyQueryResponse),
        );
        expect(marked).toStrictEqual(true);
    }
}

/**
 * Forward an outgoing to-device message returned by one OlmMachine into another OlmMachine.
 */
export async function forwardToDeviceMessage(
    sendingUser: UserId,
    recipientMachine: OlmMachine,
    toDeviceRequest: ToDeviceRequest,
): Promise<void> {
    expect(toDeviceRequest).toBeInstanceOf(ToDeviceRequest);
    await sendToDeviceMessageIntoMachine(
        sendingUser,
        toDeviceRequest.event_type,
        JSON.parse(toDeviceRequest.body).messages[recipientMachine.userId.toString()][
            recipientMachine.deviceId.toString()
        ],
        recipientMachine,
    );
}

/**
 * Send a to-device message into an OlmMachine.
 */
export async function sendToDeviceMessageIntoMachine(
    sendingUser: UserId,
    eventType: string,
    content: object,
    recipientMachine: OlmMachine,
): Promise<void> {
    await recipientMachine.receiveSyncChanges(
        JSON.stringify([
            {
                sender: sendingUser.toString(),
                type: eventType,
                content: content,
            },
        ]),
        new DeviceLists(),
        new Map(),
        undefined,
    );
}

/**
 * Have `senderMachine` claim one of `receiverMachine`'s OTKs, to establish an olm session.
 *
 * Requires that `senderMachine` already know about `receiverMachine`, normally via
 * `addMachineToMachine(receiverMachine, senderMachine)`.
 */
export async function establishOlmSession(senderMachine: OlmMachine, receiverMachine: OlmMachine) {
    const keysClaimRequest = await senderMachine.getMissingSessions([receiverMachine.userId]);
    const keysClaimRequestBody = JSON.parse(keysClaimRequest!.body);
    expect(keysClaimRequestBody.one_time_keys).toEqual({
        [receiverMachine.userId.toString()]: { [receiverMachine.deviceId.toString()]: "signed_curve25519" },
    });

    const outgoing = await receiverMachine.outgoingRequests();
    const keysUploadRequest = outgoing.find((req) => req instanceof KeysUploadRequest);
    expect(keysUploadRequest).toBeDefined();
    const keysUploadRequestBody = JSON.parse(keysUploadRequest!.body);
    const [otk_id, otk] = Object.entries(keysUploadRequestBody.one_time_keys)[0];

    const keysClaimResponse = {
        one_time_keys: {
            [receiverMachine.userId.toString()]: { [receiverMachine.deviceId.toString()]: { [otk_id]: otk } },
        },
    };

    await senderMachine.markRequestAsSent(
        keysClaimRequest!.id,
        RequestType.KeysClaim,
        JSON.stringify(keysClaimResponse),
    );
}

/**
 * Encrypt an event using the given OlmMachine. Returns the JSON for the encrypted event.
 *
 * Assumes that a megolm session has already been established.
 */
export async function encryptEvent(
    senderMachine: OlmMachine,
    room: RoomId,
    eventType: string,
    eventContent: string,
): Promise<string> {
    return JSON.stringify({
        sender: senderMachine.userId.toString(),
        event_id: `\$${Date.now()}:example.com`,
        type: "m.room.encrypted",
        origin_server_ts: Date.now(),
        content: JSON.parse(await senderMachine.encryptRoomEvent(room, eventType, eventContent)),
    });
}
