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
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.util.io.Streams;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.DocumentSignatureType;
import org.pgpainless.encryption_signing.EncryptionStream;
import org.pgpainless.encryption_signing.ProducerOptions;
import org.pgpainless.encryption_signing.SigningOptions;
import org.pgpainless.key.info.KeyRingInfo;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import sop.Ready;
import sop.operation.Sign;
import sop.SwappableOutputStream;
import sop.enums.SignAs;
import sop.exception.SOPGPException;

public class SignImpl implements Sign {

    private boolean armor = true;
    private SignAs mode = SignAs.Binary;
    private List<PGPSecretKeyRing> keys = new ArrayList<>();
    private SigningOptions signingOptions = new SigningOptions();

    @Override
    public Sign noArmor() {
        armor = false;
        return this;
    }

    @Override
    public Sign mode(SignAs mode) {
        this.mode = mode;
        return this;
    }

    @Override
    public Sign key(InputStream keyIn) throws SOPGPException.KeyIsProtected, SOPGPException.BadData, IOException {
        try {
            PGPSecretKeyRing key = PGPainless.readKeyRing().secretKeyRing(keyIn);
            KeyRingInfo info = new KeyRingInfo(key);
            if (!info.isFullyDecrypted()) {
                throw new SOPGPException.KeyIsProtected();
            }
            signingOptions.addDetachedSignature(SecretKeyRingProtector.unprotectedKeys(), key, modeToSigType(mode));
        } catch (PGPException e) {
            throw new SOPGPException.BadData(e);
        }
        return this;
    }

    @Override
    public Ready data(InputStream data) throws IOException {
        SwappableOutputStream swappableOutputStream = new SwappableOutputStream();
        try {
            EncryptionStream signingStream = PGPainless.encryptAndOrSign()
                    .onOutputStream(swappableOutputStream)
                    .withOptions(ProducerOptions.sign(signingOptions)
                            .setAsciiArmor(armor));

            return new Ready() {
                @Override
                public void writeTo(OutputStream outputStream) throws IOException {

                    if (signingStream.isClosed()) {
                        throw new IllegalStateException("EncryptionStream is already closed.");
                    }

                    swappableOutputStream.setUnderlyingStream(outputStream);
                    Streams.pipeAll(data, signingStream);
                    signingStream.close();
                }
            };

        } catch (PGPException e) {
            throw new RuntimeException(e);
        }

    }

    private static DocumentSignatureType modeToSigType(SignAs mode) {
        return mode == SignAs.Binary ? DocumentSignatureType.BINARY_DOCUMENT
                : DocumentSignatureType.CANONICAL_TEXT_DOCUMENT;
    }
}
