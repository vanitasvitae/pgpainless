/*
 * Copyright 2018 Paul Schaub.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.vanitasvitae.crypto.pgpainless;

import static junit.framework.TestCase.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;
import java.util.Collections;
import java.util.logging.Level;
import java.util.logging.Logger;

import de.vanitasvitae.crypto.pgpainless.algorithm.PublicKeyAlgorithm;
import de.vanitasvitae.crypto.pgpainless.decryption_verification.DecryptionStream;
import de.vanitasvitae.crypto.pgpainless.decryption_verification.PainlessResult;
import de.vanitasvitae.crypto.pgpainless.key.SecretKeyRingProtector;
import de.vanitasvitae.crypto.pgpainless.key.UnprotectedKeysProtector;
import de.vanitasvitae.crypto.pgpainless.key.generation.type.length.RsaLength;
import de.vanitasvitae.crypto.pgpainless.util.BCUtil;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.util.io.Streams;
import org.junit.Ignore;
import org.junit.Test;

public class EncryptDecryptTest extends AbstractPGPainlessTest {

    private static final Logger LOGGER = Logger.getLogger(EncryptDecryptTest.class.getName());
    private static final Charset UTF8 = Charset.forName("UTF-8");

    private static final String testMessage = "Ah, Juliet, if the measure of thy joy\n" +
            "Be heaped like mine, and that thy skill be more\n" +
            "To blazon it, then sweeten with thy breath\n" +
            "This neighbor air, and let rich music’s tongue\n" +
            "Unfold the imagined happiness that both\n" +
            "Receive in either by this dear encounter.";

    public EncryptDecryptTest() {
        LOGGER.log(Level.INFO, "Plain Length: " + testMessage.getBytes(UTF8).length);
    }

    @Test
    public void freshKeysRsaToRsaTest()
            throws PGPException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException,
            IOException {
        PGPSecretKeyRing sender = PGPainless.generateKeyRing().simpleRsaKeyRing("hatter@wonderland.lit", RsaLength._4096);
        PGPSecretKeyRing recipient = PGPainless.generateKeyRing().simpleRsaKeyRing("alice@wonderland.lit", RsaLength._4096);

        encryptDecryptForSecretKeyRings(sender, recipient);
    }

    @Test
    public void freshKeysEcToEcTest() throws IOException, PGPException, NoSuchAlgorithmException, NoSuchProviderException,
            InvalidAlgorithmParameterException {
        PGPSecretKeyRing sender = PGPainless.generateKeyRing().simpleEcKeyRing("hatter@wonderland.lit");
        PGPSecretKeyRing recipient = PGPainless.generateKeyRing().simpleEcKeyRing("alice@wonderland.lit");

        encryptDecryptForSecretKeyRings(sender, recipient);
    }

    @Test
    public void freshKeysEcToRsaTest()
            throws PGPException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException,
            IOException {
        PGPSecretKeyRing sender = PGPainless.generateKeyRing().simpleEcKeyRing("hatter@wonderland.lit");
        PGPSecretKeyRing recipient = PGPainless.generateKeyRing().simpleRsaKeyRing("alice@wonderland.lit", RsaLength._4096);

        encryptDecryptForSecretKeyRings(sender, recipient);
    }

    @Test
    public void freshKeysRsaToEcTest()
            throws PGPException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException,
            IOException {
        PGPSecretKeyRing sender = PGPainless.generateKeyRing().simpleRsaKeyRing("hatter@wonderland.lit", RsaLength._4096);
        PGPSecretKeyRing recipient = PGPainless.generateKeyRing().simpleEcKeyRing("alice@wonderland.lit");

        encryptDecryptForSecretKeyRings(sender, recipient);
    }

    @Ignore
    private void encryptDecryptForSecretKeyRings(PGPSecretKeyRing sender, PGPSecretKeyRing recipient)
            throws PGPException,
            IOException {
        PGPPublicKeyRing recipientPub = BCUtil.publicKeyRingFromSecretKeyRing(recipient);
        PGPPublicKeyRing senderPub = BCUtil.publicKeyRingFromSecretKeyRing(sender);

        SecretKeyRingProtector keyDecryptor = new UnprotectedKeysProtector();

        byte[] secretMessage = (testMessage).getBytes(UTF8);

        ByteArrayOutputStream envelope = new ByteArrayOutputStream();

        OutputStream encryptor = PGPainless.createEncryptor()
                .onOutputStream(envelope)
                .toRecipients(recipientPub)
                .usingSecureAlgorithms()
                .signWith(keyDecryptor, sender)
                .noArmor();

        Streams.pipeAll(new ByteArrayInputStream(secretMessage), encryptor);
        encryptor.close();
        byte[] encryptedSecretMessage = envelope.toByteArray();

        LOGGER.log(Level.INFO, "Sender: " + PublicKeyAlgorithm.fromId(sender.getPublicKey().getAlgorithm()) +
        " Receiver: " + PublicKeyAlgorithm.fromId(recipient.getPublicKey().getAlgorithm()) +
        " Encrypted Length: " + encryptedSecretMessage.length);

        // Juliet trieth to comprehend Romeos words

        ByteArrayInputStream envelopeIn = new ByteArrayInputStream(encryptedSecretMessage);
        DecryptionStream decryptor = PGPainless.createDecryptor()
                .onInputStream(envelopeIn)
                .decryptWith(BCUtil.keyRingsToKeyRingCollection(recipient), keyDecryptor)
                .verifyWith(Collections.singleton(TestKeys.ROMEO_KEY_ID), BCUtil.keyRingsToKeyRingCollection(senderPub))
                .ignoreMissingPublicKeys()
                .build();

        OutputStream decryptedSecretMessage = new ByteArrayOutputStream();

        Streams.pipeAll(decryptor, decryptedSecretMessage);
        decryptor.close();

        assertTrue(Arrays.equals(secretMessage, ((ByteArrayOutputStream) decryptedSecretMessage).toByteArray()));
        PainlessResult result = decryptor.getResult();
        assertTrue(result.containsVerifiedSignatureFrom(senderPub));
        assertTrue(result.isIntegrityProtected());
        assertTrue(result.isSigned());
        assertTrue(result.isEncrypted());
        assertTrue(result.isVerified());
    }
}
