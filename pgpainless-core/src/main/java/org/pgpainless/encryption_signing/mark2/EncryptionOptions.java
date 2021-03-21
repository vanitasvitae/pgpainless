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

import org.pgpainless.algorithm.CompressionAlgorithm;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.encryption_signing.EncryptionStream;

public class EncryptionOptions {

    private EncryptionStream.Purpose purpose = EncryptionStream.Purpose.STORAGE_AND_COMMUNICATIONS;
    private boolean customEncryptionAlgorithm = false;
    private SymmetricKeyAlgorithm encryptionAlgorithm = null;
    private boolean customCompressionAlgorithm = false;
    private CompressionAlgorithm compressionAlgorithm = null;

    public static EncryptionOptions defaultOptions() {
        return new EncryptionOptions();
    }

    public boolean isCustomEncryptionAlgorithm() {
        return customEncryptionAlgorithm;
    }

    public SymmetricKeyAlgorithm getEncryptionAlgorithm() {
        return encryptionAlgorithm;
    }

    public EncryptionOptions setEncryptionAlgorithm(SymmetricKeyAlgorithm encryptionAlgorithm) {
        this.encryptionAlgorithm = encryptionAlgorithm;
        this.customEncryptionAlgorithm = true;
        return this;
    }

    public EncryptionOptions setCompressionAlgorithm(CompressionAlgorithm compressionAlgorithm) {
        this.compressionAlgorithm = compressionAlgorithm;
        this.customCompressionAlgorithm = true;
        return this;
    }

    public boolean isCustomCompressionAlgorithm() {
        return customCompressionAlgorithm;
    }

    public CompressionAlgorithm getCompressionAlgorithm() {
        return compressionAlgorithm;
    }
}
