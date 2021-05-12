package org.pgpainless.decryption_verification;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.key.TestKeys;

public class ClearSignTest {

    @Test
    public void testClearSignedMessageVerification() throws IOException, PGPException {
        String message = "-----BEGIN PGP SIGNED MESSAGE-----\n" +
                "Hash: SHA512\n" +
                "\n" +
                "This message is encrypted\n" +
                "-----BEGIN PGP SIGNATURE-----\n" +
                "\n" +
                "iHUEARMKAB0WIQRPZlxNwsRmC8ZCXkFXNuaTGs83DAUCYJgtgAAKCRBXNuaTGs83\n" +
                "DMwnAP4ifGe9nVDQb+wc2xNCxJLfnT1U5wE1HiEddigjbq/ZNQEAtuUhxHOZYtvt\n" +
                "G3DTBQu3CBGAGIR7K2EyKdXlUha0BXA=\n" +
                "=smfK\n" +
                "-----END PGP SIGNATURE-----\n";

        PGPPublicKeyRing publicKeys = TestKeys.getEmilPublicKeyRing();

        DecryptionStream verifier = PGPainless.decryptAndOrVerify().onInputStream(new ByteArrayInputStream(message.getBytes(StandardCharsets.UTF_8)))
                .doNotDecrypt()
                .verifyWith(publicKeys)
                .ignoreMissingPublicKeys()
                .build();

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Streams.pipeAll(verifier, out);

        verifier.close();
        OpenPgpMetadata metadata = verifier.getResult();
        assertTrue(metadata.getVerifiedSignatureKeyFingerprints().contains(TestKeys.EMIL_FINGERPRINT));
    }
}
