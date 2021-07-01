/*
 * Copyright 2021 Paul Schaub.
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
package org.pgpainless.sop;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Date;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.util.io.Streams;
import org.pgpainless.PGPainless;
import org.pgpainless.decryption_verification.ConsumerOptions;
import org.pgpainless.decryption_verification.DecryptionStream;
import org.pgpainless.decryption_verification.OpenPgpMetadata;
import org.pgpainless.exception.NotYetImplementedException;
import org.pgpainless.key.info.KeyRingInfo;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.util.Passphrase;
import sop.operation.Decrypt;
import sop.ReadyWithResult;
import sop.SessionKey;
import sop.exception.SOPGPException;

public class DecryptImpl implements Decrypt<OpenPgpMetadata> {

    private final ConsumerOptions consumerOptions = new ConsumerOptions();

    @Override
    public DecryptImpl verifyNotBefore(Date timestamp) throws SOPGPException.UnsupportedOption {
        try {
            consumerOptions.verifyNotBefore(timestamp);
        } catch (NotYetImplementedException e) {
            throw new SOPGPException.UnsupportedOption();
        }
        return this;
    }

    @Override
    public DecryptImpl verifyNotAfter(Date timestamp) throws SOPGPException.UnsupportedOption {
        try {
            consumerOptions.verifyNotAfter(timestamp);
        } catch (NotYetImplementedException e) {
            throw new SOPGPException.UnsupportedOption();
        }
        return this;
    }

    @Override
    public DecryptImpl verifyWithCert(InputStream certIn) throws SOPGPException.CertCannotSign, SOPGPException.BadData, IOException {
        try {
            PGPPublicKeyRingCollection certs = PGPainless.readKeyRing().keyRingCollection(certIn, false)
                    .getPgpPublicKeyRingCollection();
            if (certs == null) {
                throw new SOPGPException.BadData(new PGPException("No certificates provided."));
            }

            consumerOptions.addVerificationCerts(certs);

        } catch (PGPException e) {
            throw new SOPGPException.BadData(e);
        }
        return this;
    }

    @Override
    public DecryptImpl withSessionKey(SessionKey sessionKey) throws SOPGPException.UnsupportedOption {
        throw new SOPGPException.UnsupportedOption();
    }

    @Override
    public DecryptImpl withPassword(String password) throws SOPGPException.PasswordNotHumanReadable, SOPGPException.UnsupportedOption {
        consumerOptions.addDecryptionPassphrase(Passphrase.fromPassword(password));
        return this;
    }

    @Override
    public DecryptImpl withKey(InputStream keyIn) throws SOPGPException.KeyIsProtected, SOPGPException.BadData, SOPGPException.UnsupportedAsymmetricAlgo {
        try {
            PGPSecretKeyRingCollection secretKeys = PGPainless.readKeyRing()
                    .keyRingCollection(keyIn, true)
                    .getPGPSecretKeyRingCollection();

            for (PGPSecretKeyRing secretKey : secretKeys) {
                KeyRingInfo info = new KeyRingInfo(secretKey);
                if (!info.isFullyDecrypted()) {
                    throw new SOPGPException.KeyIsProtected();
                }
            }

            consumerOptions.addDecryptionKeys(secretKeys, SecretKeyRingProtector.unprotectedKeys());
        } catch (IOException | PGPException e) {
            throw new SOPGPException.BadData(e);
        }
        return this;
    }

    @Override
    public ReadyWithResult<OpenPgpMetadata> ciphertext(InputStream ciphertext) throws SOPGPException.BadData {
        DecryptionStream decryptionStream;
        try {
            decryptionStream = PGPainless.decryptAndOrVerify()
                    .onInputStream(ciphertext)
                    .withOptions(consumerOptions);
        } catch (PGPException | IOException e) {
            throw new SOPGPException.BadData(e);
        }

        return new ReadyWithResult<OpenPgpMetadata>() {
            @Override
            public OpenPgpMetadata writeTo(OutputStream outputStream) throws IOException {
                Streams.pipeAll(decryptionStream, outputStream);
                decryptionStream.close();
                return decryptionStream.getResult();
            }
        };
    }
}
