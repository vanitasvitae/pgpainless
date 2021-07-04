package org.pgpainless.sop;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.util.io.Streams;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.DocumentSignatureType;
import org.pgpainless.encryption_signing.EncryptionOptions;
import org.pgpainless.encryption_signing.EncryptionStream;
import org.pgpainless.encryption_signing.ProducerOptions;
import org.pgpainless.encryption_signing.SigningOptions;
import org.pgpainless.exception.WrongPassphraseException;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.util.Passphrase;
import sop.Ready;
import sop.SwappableOutputStream;
import sop.enums.EncryptAs;
import sop.exception.SOPGPException;
import sop.operation.Encrypt;

public class EncryptImpl implements Encrypt {

    EncryptionOptions encryptionOptions = new EncryptionOptions();
    SigningOptions signingOptions = null;

    boolean armor = true;

    @Override
    public Encrypt noArmor() {
        armor = false;
        return this;
    }

    @Override
    public Encrypt mode(EncryptAs mode) throws SOPGPException.UnsupportedOption {
        // TODO: Move EncryptAs to ProducerOptions
        // throw new SOPGPException.UnsupportedOption();
        return this;
    }

    @Override
    public Encrypt signWith(InputStream keyIn) throws SOPGPException.KeyIsProtected, SOPGPException.CertCannotSign, SOPGPException.UnsupportedAsymmetricAlgo, SOPGPException.BadData {
        try {
            PGPSecretKeyRingCollection keys = PGPainless.readKeyRing().secretKeyRingCollection(keyIn);

            if (signingOptions == null) {
                signingOptions = SigningOptions.get();
            }
            try {
                signingOptions.addInlineSignatures(SecretKeyRingProtector.unprotectedKeys(), keys, DocumentSignatureType.BINARY_DOCUMENT);
            } catch (IllegalArgumentException e) {
                throw new SOPGPException.CertCannotSign();
            } catch (WrongPassphraseException e) {
                throw new SOPGPException.KeyIsProtected();
            }
        } catch (IOException | PGPException e) {
            throw new SOPGPException.BadData(e);
        }
        return this;
    }

    @Override
    public Encrypt withPassword(String password) throws SOPGPException.PasswordNotHumanReadable, SOPGPException.UnsupportedOption {
        encryptionOptions.addPassphrase(Passphrase.fromPassword(password));
        return this;
    }

    @Override
    public Encrypt withCert(InputStream cert) throws SOPGPException.CertCannotEncrypt, SOPGPException.UnsupportedAsymmetricAlgo, SOPGPException.BadData {
        try {
            PGPPublicKeyRingCollection certificates = PGPainless.readKeyRing().publicKeyRingCollection(cert);
            encryptionOptions.addRecipients(certificates);
        } catch (IOException | PGPException e) {
            throw new SOPGPException.BadData(e);
        }
        return this;
    }

    @Override
    public Ready plaintext(InputStream plaintext) throws IOException {
        ProducerOptions producerOptions = signingOptions != null ?
                ProducerOptions.signAndEncrypt(encryptionOptions, signingOptions) :
                ProducerOptions.encrypt(encryptionOptions);
        producerOptions.setAsciiArmor(armor);

        try {
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            EncryptionStream encryptionStream = PGPainless.encryptAndOrSign()
                    .onOutputStream(buffer)
                    .withOptions(producerOptions);

            return new Ready() {
                @Override
                public void writeTo(OutputStream outputStream) throws IOException {
                    Streams.pipeAll(plaintext, encryptionStream);
                    encryptionStream.close();
                    Streams.pipeAll(new ByteArrayInputStream(buffer.toByteArray()), outputStream);
                }
            };
        } catch (PGPException e) {
            throw new IOException();
        }
    }
}
