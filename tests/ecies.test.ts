const {
    Ecies,
    SecretsBundle,
    UserId,
    DeviceId,
    OlmMachine,
    RequestType,
} = require("@matrix-org/matrix-sdk-crypto-wasm");

describe(Ecies.name, () => {
    test("can establish a channel and decrypt the initial message", () => {
        const alice = new Ecies();
        const bob = new Ecies();

        const { initial_message, channel: alice_established } = alice.establish_outbound_channel(
            bob.public_key(),
            "It's a secret to everybody",
        );

        const { message, channel } = bob.establish_inbound_channel(initial_message);
        expect(message).toStrictEqual("It's a secret to everybody");

        const alice_check = alice_established.check_code();
        const bob_check = channel.check_code();

        expect(alice_check.as_bytes()).toStrictEqual(bob_check.as_bytes());
        expect(alice_check.to_digit()).toStrictEqual(bob_check.to_digit());
        expect(alice_check.toDigitNoLeadingZero()).toStrictEqual(bob_check.toDigitNoLeadingZero());

        const ciphertext = channel.encrypt("Other message");
        const second_plaintext = alice_established.decrypt(ciphertext);

        expect(message).toStrictEqual("It's a secret to everybody");
        expect(second_plaintext).toStrictEqual("Other message");
    });
});

describe(SecretsBundle.name, () => {
    test("can deserialize a secrets bundle", async () => {
        const json = {
            type: "m.login.secrets",
            cross_signing: {
                master_key: "bMnVpkHI4S2wXRxy+IpaKM5PIAUUkl6DE+n0YLIW/qs",
                user_signing_key: "8tlgLjUrrb/zGJo4YKGhDTIDCEjtJTAS/Sh2AGNLuIo",
                self_signing_key: "pfDknmP5a0fVVRE54zhkUgJfzbNmvKcNfIWEW796bQs",
            },
            backup: {
                algorithm: "m.megolm_backup.v1.curve25519-aes-sha2",
                key: "bYYv3aFLQ49jMNcOjuTtBY9EKDby2x1m3gfX81nIKRQ",
                backup_version: "9",
            },
        };

        const cycle = JSON.parse(JSON.stringify(json));
        const bundle = SecretsBundle.from_json(cycle);

        expect(bundle.masterKey).toStrictEqual("bMnVpkHI4S2wXRxy+IpaKM5PIAUUkl6DE+n0YLIW/qs");
    });

    test("can import a secrets bundle", async () => {
        const userId = new UserId("@alice:example.org");
        const firstDevice = new DeviceId("ABCDEF");
        const secondDevice = new DeviceId("DEVICE2");

        const firstMachine = await OlmMachine.initialize(userId, firstDevice);
        const secondMachine = await OlmMachine.initialize(userId, secondDevice);

        await firstMachine.bootstrapCrossSigning(false);
        const bundle = await firstMachine.exportSecretsBundle();

        const alice = new Ecies();
        const bob = new Ecies();

        const json_bundle = bundle.to_json();

        const { initial_message } = alice.establish_outbound_channel(bob.public_key(), JSON.stringify(json_bundle));
        const { message } = bob.establish_inbound_channel(initial_message);

        const deserialize_message = JSON.parse(message);
        const received_bundle = SecretsBundle.from_json(deserialize_message);

        await secondMachine.importSecretsBundle(received_bundle);

        const crossSigningStatus = await secondMachine.crossSigningStatus();
        expect(crossSigningStatus.hasMaster).toStrictEqual(true);
        expect(crossSigningStatus.hasSelfSigning).toStrictEqual(true);
        expect(crossSigningStatus.hasUserSigning).toStrictEqual(true);

        const exported_bundle = await secondMachine.exportSecretsBundle();

        expect(exported_bundle.masterKey).toStrictEqual(bundle.masterKey);
        expect(exported_bundle.selfSigningKey).toStrictEqual(bundle.selfSigningKey);
        expect(exported_bundle.userSigningKey).toStrictEqual(bundle.userSigningKey);

        const identity = await secondMachine.getIdentity(userId);
        expect(identity.isVerified).toBeTruthy();
    });
});
