const { QrCodeData, QrCodeIntent, Curve25519PublicKey } = require("@matrix-org/matrix-sdk-crypto-wasm");

describe(QrCodeData.name, () => {
    test("can parse the QR code bytes from the MSC", () => {
        // Parse a QrCodeData from its serialised form
        // Should match https://github.com/matrix-org/matrix-rust-sdk/blob/main/crates/matrix-sdk-crypto/src/types/qr_login/msc_4108.rs#L251
        const base64Input =
            "TUFUUklYAgPYhmhqshl7eA4wCp1KIUdIBwDXkp85qzG55RQ3AkjtawBHaHR0cHM6Ly9yZW5kZXp2b3VzLmxhYi5lbGVtZW50LmRldi9lOGRhNjM1NS01NTBiLTRhMzItYTE5My0xNjE5ZDk4MzA2Njg";

        const data = QrCodeData.fromBase64(base64Input);

        // Validate that it was deserialised correctly
        expect(data.publicKey.toBase64()).toStrictEqual("2IZoarIZe3gOMAqdSiFHSAcA15KfOasxueUUNwJI7Ws");
        expect(data.rendezvousUrl).toStrictEqual(
            "https://rendezvous.lab.element.dev/e8da6355-550b-4a32-a193-1619d9830668",
        );
        expect(data.mode).toStrictEqual(QrCodeIntent.Login);

        // Verify that a full round-trip gets back to our initial input
        const serialised = data.toBase64();
        expect(serialised).toStrictEqual(base64Input);
    });

    test("can construct a new QrCodeData class", () => {
        // Construct a QrCodeData
        const publicKeyBase64 = "2IZoarIZe3gOMAqdSiFHSAcA15KfOasxueUUNwJI7Ws";
        const publicKey = new Curve25519PublicKey(publicKeyBase64);
        const rendezvousUrl = "https://rendezvous.lab.element.dev/e8da6355-550b-4a32-a193-1619d9830668";

        // Extract its parts and validate they come out correctly
        const data = new QrCodeData(publicKey, rendezvousUrl);

        expect(data.publicKey.toBase64()).toStrictEqual(publicKeyBase64);
        expect(data.rendezvousUrl).toStrictEqual(rendezvousUrl);
        expect(data.mode).toStrictEqual(QrCodeIntent.Login);

        // Check the complete serialisation produces the exact expected result.
        // Should match https://github.com/matrix-org/matrix-rust-sdk/blob/main/crates/matrix-sdk-crypto/src/types/qr_login/msc_4108.rs#L251
        const expectedSerialised =
            "TUFUUklYAgPYhmhqshl7eA4wCp1KIUdIBwDXkp85qzG55RQ3AkjtawBHaHR0cHM6Ly9yZW5kZXp2b3VzLmxhYi5lbGVtZW50LmRldi9lOGRhNjM1NS01NTBiLTRhMzItYTE5My0xNjE5ZDk4MzA2Njg";
        const serialised = data.toBase64();
        expect(serialised).toStrictEqual(expectedSerialised);
    });

    test("can round-trip an MSC4388 QrCodeData class", () => {
        // Deserialise from a known base 64 representation
        // Should match https://github.com/matrix-org/matrix-rust-sdk/blob/main/crates/matrix-sdk-crypto/src/types/qr_login/msc_4388.rs#L339
        const serialisedInput =
            "SU9fRUxFTUVOVF9NU0M0Mzg4AwG0yzZ1QVpQ1jlnoxWX3d5jrWRFfELxjS2gN7pz9y+3PBowMUhYOUswMFExSDZLUEQ0N0VHNEcxVDNYRyRodHRwczovL3N5bmFwc2Utb2lkYy5sYWIuZWxlbWVudC5kZXY";

        const qrCodeData = QrCodeData.fromBase64(serialisedInput);

        // Check the fields deserialised as expected
        const publicKeyBase64 = "tMs2dUFaUNY5Z6MVl93eY61kRXxC8Y0toDe6c/cvtzw";
        const rendezvousId = "01HX9K00Q1H6KPD47EG4G1T3XG";
        const baseUrl = "https://synapse-oidc.lab.element.dev/";

        expect(qrCodeData.publicKey.toBase64()).toStrictEqual(publicKeyBase64);
        expect(qrCodeData.mode).toStrictEqual(QrCodeIntent.Reciprocate);

        const mscData = qrCodeData.intentData.msc4388;
        expect(mscData).toBeDefined();
        expect(mscData.rendezvousId).toStrictEqual(rendezvousId);
        expect(mscData.baseUrl).toStrictEqual(baseUrl);

        // Serialise and check the round-trip is correct
        const serialised = qrCodeData.toBase64();
        expect(serialised).toStrictEqual(serialisedInput);
    });

    test("can construct a new MSC4388 QrCodeData class", () => {
        // Construct a QrCodeData
        const publicKeyBase64 = "tMs2dUFaUNY5Z6MVl93eY61kRXxC8Y0toDe6c/cvtzw";
        const publicKey = new Curve25519PublicKey(publicKeyBase64);
        const rendezvousId = "01HX9K00Q1H6KPD47EG4G1T3XG";
        const baseUrl = "https://synapse-oidc.lab.element.dev/";

        const qrCodeData = QrCodeData.newMsc4388(publicKey, rendezvousId, baseUrl, QrCodeIntent.Reciprocate);

        // Extract its parts and validate they come out correctly
        expect(qrCodeData.publicKey.toBase64()).toStrictEqual(publicKeyBase64);
        expect(qrCodeData.mode).toStrictEqual(QrCodeIntent.Reciprocate);

        const mscData = qrCodeData.intentData.msc4388;
        expect(mscData).toBeDefined();
        expect(mscData.rendezvousId).toStrictEqual(rendezvousId);
        expect(mscData.baseUrl).toStrictEqual(baseUrl);

        // Note: if we serialise this back to base64, it won't quite match the serialised form of the previous test,
        // even though its parts are all the same. This is because the baseUrl gets normalised by Url::parse inside
        // QrCodeData.newMsc4388.
        //
        // So we don't check the serialisation here - the previous test should be adequate.
    });
});
