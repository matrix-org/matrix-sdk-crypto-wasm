const { QrCodeData, QrCodeIntent, Curve25519PublicKey } = require("@matrix-org/matrix-sdk-crypto-wasm");

describe(QrCodeData.name, () => {
    test("can parse the QR code bytes from the MSC", () => {
        const base64Data =
            "TUFUUklYAgPYhmhqshl7eA4wCp1KIUdIBwDXkp85qzG55RQ3AkjtawBHaHR0cHM6Ly9yZW5kZXp2b3VzLmxhYi5lbGVtZW50LmRldi9lOGRhNjM1NS01NTBiLTRhMzItYTE5My0xNjE5ZDk4MzA2Njg";

        const data = QrCodeData.fromBase64(base64Data);

        expect(data.publicKey.toBase64()).toStrictEqual("2IZoarIZe3gOMAqdSiFHSAcA15KfOasxueUUNwJI7Ws");
        expect(data.rendezvousUrl).toStrictEqual(
            "https://rendezvous.lab.element.dev/e8da6355-550b-4a32-a193-1619d9830668",
        );
        expect(data.mode).toStrictEqual(QrCodeIntent.Login);

        const encoded = data.toBase64();

        expect(base64Data).toStrictEqual(encoded);
    });

    test("can construct a new QrCodeData class", () => {
        const base64Data =
            "TUFUUklYAgPYhmhqshl7eA4wCp1KIUdIBwDXkp85qzG55RQ3AkjtawBHaHR0cHM6Ly9yZW5kZXp2b3VzLmxhYi5lbGVtZW50LmRldi9lOGRhNjM1NS01NTBiLTRhMzItYTE5My0xNjE5ZDk4MzA2Njg";
        const publicKey = new Curve25519PublicKey("2IZoarIZe3gOMAqdSiFHSAcA15KfOasxueUUNwJI7Ws");
        const rendezvousUrl = "https://rendezvous.lab.element.dev/e8da6355-550b-4a32-a193-1619d9830668";

        const data = new QrCodeData(publicKey, rendezvousUrl);

        expect(data.publicKey.toBase64()).toStrictEqual("2IZoarIZe3gOMAqdSiFHSAcA15KfOasxueUUNwJI7Ws");
        expect(data.rendezvousUrl).toStrictEqual(rendezvousUrl);
        expect(data.mode).toStrictEqual(QrCodeIntent.Login);

        const encoded = data.toBase64();
        expect(base64Data).toStrictEqual(encoded);
    });

    test("can construct a new MSC4388 QrCodeData class", () => {
        const base64Data =
            "SU9fRUxFTUVOVF9NU0M0Mzg4AwG0yzZ1QVpQ1jlnoxWX3d5jrWRFfELxjS2gN7pz9y+3PAAaMDFIWDlLMDBRMUg2S1BENDdFRzRHMVQzWEcAJGh0dHBzOi8vc3luYXBzZS1vaWRjLmxhYi5lbGVtZW50LmRldg";

        const publicKey = new Curve25519PublicKey("tMs2dUFaUNY5Z6MVl93eY61kRXxC8Y0toDe6c/cvtzw");
        const rendezvousId = "01HX9K00Q1H6KPD47EG4G1T3XG";
        const baseUrl = "https://synapse-oidc.lab.element.dev/";

        const data = QrCodeData.newMsc4388(publicKey, rendezvousId, baseUrl, QrCodeIntent.Reciprocate);

        expect(data.publicKey.toBase64()).toStrictEqual("tMs2dUFaUNY5Z6MVl93eY61kRXxC8Y0toDe6c/cvtzw");
        expect(data.mode).toStrictEqual(QrCodeIntent.Reciprocate);

        const intentData = data.intentData;
        const mscData = intentData.msc4388;

        expect(mscData).toBeDefined();
        expect(mscData.rendezvousId).toStrictEqual(rendezvousId);
        expect(mscData.baseUrl).toStrictEqual(baseUrl);

        const encoded = data.toBase64();
        expect(base64Data).toStrictEqual(encoded);
    });
});
