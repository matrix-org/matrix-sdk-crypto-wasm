const {
    HpkeRecipientChannel,
    HpkeSenderChannel,
    SecretsBundle,
    UserId,
    DeviceId,
    OlmMachine,
    RequestType,
} = require("@matrix-org/matrix-sdk-crypto-wasm");

describe("HPKE channel creation", () => {
    test("can establish a channel and decrypt the initial message", () => {
        const alice = new HpkeSenderChannel();
        const bob = new HpkeRecipientChannel();

        const { message, channel: aliceUnidirectional } = alice.establishChannel(
            bob.publicKey,
            "It's a secret to everybody",
            "AAD"
        );

        const { message: initialMessage, channel: bobUnidirectional } = bob.establishChannel(message, "AAD");
        expect(initialMessage).toStrictEqual("It's a secret to everybody");

        const { initialResponse, channel: bobEstablished } = bobUnidirectional.establishBidirectionalChannel("Initial response", "AAD2");
        const { initialResponse: secondPlaintext, channel: aliceEstablished } = aliceUnidirectional.establishBidirectionalChannel(initialResponse, "AAD2");

        expect(secondPlaintext).toStrictEqual("Initial response");

        const aliceCheck = aliceEstablished.checkCode;
        const bobCheck = bobEstablished.checkCode;

        expect(aliceCheck.as_bytes()).toStrictEqual(bobCheck.as_bytes());
        expect(aliceCheck.to_digit()).toStrictEqual(bobCheck.to_digit());

        const ciphertext = bobEstablished.seal("Other message", "");
        const thirdPlaintext = aliceEstablished.open(ciphertext, "");

        expect(thirdPlaintext).toStrictEqual("Other message");
    });
});
