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
package org.pgpainless.encryption_signing.mark2;

import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.CompressionAlgorithm;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.policy.Policy;
import org.pgpainless.util.Passphrase;

public class EncryptionBuilder2Impl
        implements EncryptionBuilder2,
        EncryptionBuilder2.ToRecipient,
        EncryptionBuilder2.AndToRecipient,
        EncryptionBuilder2.OptionalRecipient,
        EncryptionBuilder2.SignWith,
        EncryptionBuilder2.AndSignWith,
        EncryptionBuilder2.OptionalSignWith {

    private final List<EncryptionMethod> encryptionMethods = new ArrayList<>();
    private final List<SignatureMethod> signatureMethods = new ArrayList<>();

    private OutputStream outputStream;
    private EncryptionOptions encryptionOptions;
    private boolean asciiArmor;

    public static EncryptionBuilder2 builder() {
        return new EncryptionBuilder2Impl();
    }

    @Override
    public ToRecipient encrypt(OutputStream outputStream, EncryptionOptions encryptionOptions) {
        this.outputStream = outputStream;
        this.encryptionOptions = encryptionOptions;
        return this;
    }

    @Override
    public SignWith noEncryption(OutputStream outputStream) {
        this.outputStream = outputStream;
        return this;
    }

    @Override
    public OptionalRecipient and() {
        return this;
    }

    @Override
    public Done noSigning() {
        return this;
    }

    @Override
    public AndSignWith inlineSignWith(SecretKeyRingProtector protector, PGPSecretKeyRing key, String userId, SigningOptions options) {
        return this;
    }

    @Override
    public AndSignWith detachedSignWith(SecretKeyRingProtector protector, PGPSecretKeyRing key, String userId, SigningOptions options) {
        return this;
    }

    @Override
    public OptionalSignWith and_() {
        return this;
    }

    @Override
    public AndToRecipient toRecipient(PGPPublicKeyRing key, String userId) {
        return this;
    }

    @Override
    public AndToRecipient toPassphrase(Passphrase passphrase) {
        return this;
    }

    @Override
    public EncryptionStream2 done() throws IOException, PGPException {

        CompressionAlgorithm compressionAlgorithm = negotiateCompression(encryptionOptions, encryptionMethods);
        SymmetricKeyAlgorithm encryptionAlgorithm = negotiateEncryption(encryptionOptions, encryptionMethods);

        return new EncryptionStream2(
                outputStream,
                encryptionMethods,
                signatureMethods,
                compressionAlgorithm,
                encryptionAlgorithm,
                asciiArmor);
    }

    private SymmetricKeyAlgorithm negotiateEncryption(EncryptionOptions encryptionOptions, List<EncryptionMethod> encryptionMethods) {
        if (encryptionOptions.isCustomEncryptionAlgorithm()) {
            return encryptionOptions.getEncryptionAlgorithm();
        }

        Policy.SymmetricKeyAlgorithmPolicy policy = PGPainless.getPolicy().getSymmetricKeyAlgorithmPolicy();

        List<SymmetricKeyAlgorithm> sharedAcrossKeys = null;
        for (EncryptionMethod encryptionMethod : encryptionMethods) {
            if (encryptionMethod instanceof EncryptionMethod.ToPassphrase) {
                continue;
            }
            EncryptionMethod.ToPublicKey keyEncryption = (EncryptionMethod.ToPublicKey) encryptionMethod;
            List<SymmetricKeyAlgorithm> supported = keyEncryption.getSupportedEncryptionAlgorithms();
            if (sharedAcrossKeys == null) {
                sharedAcrossKeys = supported;
            } else {
                sharedAcrossKeys.retainAll(supported);
            }
        }
        // No preferences => follow our policy
        if (sharedAcrossKeys == null) {
            return policy.getDefaultSymmetricKeyAlgorithm();
        }

        // remove unacceptable algorithms from shared preferences
        for (int i = sharedAcrossKeys.size() - 1; i >= 0; i--) {
            SymmetricKeyAlgorithm algorithm = sharedAcrossKeys.get(i);
            if (!policy.isAcceptable(algorithm)) {
                sharedAcrossKeys.remove(i);
            }
        }

        if (sharedAcrossKeys.isEmpty()) {
            return policy.getDefaultSymmetricKeyAlgorithm();
        } else {
            // TODO: Return "best" algorithm, maybe by sorting
            return sharedAcrossKeys.get(0);
        }
    }

    private CompressionAlgorithm negotiateCompression(EncryptionOptions encryptionOptions, List<EncryptionMethod> encryptionMethods) {
        if (encryptionOptions.isCustomCompressionAlgorithm()) {
            return encryptionOptions.getCompressionAlgorithm();
        }

        List<CompressionAlgorithm> compressionAlgorithms = Arrays.asList(
                // TODO: This is an arbitrary order.
                CompressionAlgorithm.ZLIB,
                CompressionAlgorithm.ZIP,
                CompressionAlgorithm.BZIP2,
                CompressionAlgorithm.UNCOMPRESSED
        );
        for (EncryptionMethod encryptionMethod : encryptionMethods) {
            if (encryptionMethod instanceof EncryptionMethod.ToPassphrase) {
                continue;
            }
            EncryptionMethod.ToPublicKey keyEncryption = (EncryptionMethod.ToPublicKey) encryptionMethod;
            List<CompressionAlgorithm> preferredCompression = keyEncryption.getSupportedCompressionAlgorithms();

            compressionAlgorithms.retainAll(preferredCompression);
        }

        if (!compressionAlgorithms.isEmpty()) {
            return compressionAlgorithms.get(0);
        }

        return CompressionAlgorithm.BZIP2;
    }
}
