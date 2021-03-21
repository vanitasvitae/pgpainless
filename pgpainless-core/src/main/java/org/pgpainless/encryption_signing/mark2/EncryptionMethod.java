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

import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.operator.PGPKeyEncryptionMethodGenerator;
import org.pgpainless.algorithm.CompressionAlgorithm;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.util.Passphrase;

public abstract class EncryptionMethod {

    public abstract PGPKeyEncryptionMethodGenerator getEncryptionMethodGenerator();

    public static class ToPassphrase extends EncryptionMethod {

        private final Passphrase passphrase;

        public ToPassphrase(Passphrase passphrase) {
            if (!passphrase.isValid() || passphrase.isEmpty()) {
                throw new IllegalArgumentException("Passphrase MUST be non-empty.");
            }
            this.passphrase = passphrase;
        }

        @Override
        public PGPKeyEncryptionMethodGenerator getEncryptionMethodGenerator() {
            return ImplementationFactory.getInstance().getPBEKeyEncryptionMethodGenerator(passphrase);
        }
    }

    public static class ToPublicKey extends EncryptionMethod {

        private final PGPPublicKey key;
        private final List<SymmetricKeyAlgorithm> symmetricKeyAlgorithmPreferences = new ArrayList<>();
        private final List<CompressionAlgorithm> compressionAlgorithmPreferences = new ArrayList<>();

        public ToPublicKey(PGPPublicKey key, List<SymmetricKeyAlgorithm> symmetricKeyAlgorithmPreferences, List<CompressionAlgorithm> compressionAlgorithmPreferences) {
            this.key = key;
            this.symmetricKeyAlgorithmPreferences.addAll(symmetricKeyAlgorithmPreferences);
            this.compressionAlgorithmPreferences.addAll(compressionAlgorithmPreferences);
        }

        public PGPPublicKey getKey() {
            return key;
        }

        @Override
        public PGPKeyEncryptionMethodGenerator getEncryptionMethodGenerator() {
            return ImplementationFactory.getInstance().getPublicKeyKeyEncryptionMethodGenerator(key);
        }

        public List<SymmetricKeyAlgorithm> getSupportedEncryptionAlgorithms() {
            return symmetricKeyAlgorithmPreferences;
        }

        public List<CompressionAlgorithm> getSupportedCompressionAlgorithms() {
            return compressionAlgorithmPreferences;
        }
    }
}
