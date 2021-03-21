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
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.operator.PGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.pgpainless.algorithm.CompressionAlgorithm;
import org.pgpainless.algorithm.SignatureType;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.decryption_verification.DetachedSignature;
import org.pgpainless.decryption_verification.OpenPgpMetadata;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.util.ArmoredOutputStreamFactory;

/**
 * This class is based upon Jens Neuhalfen's Bouncy-GPG PGPEncryptingStream.
 * @see <a href="https://github.com/neuhalje/bouncy-gpg/blob/master/src/main/java/name/neuhalfen/projects/crypto/bouncycastle/openpgp/encrypting/PGPEncryptingStream.java">Source</a>
 */
public final class EncryptionStream2 extends OutputStream {

    public enum Purpose {
        /**
         * The stream will encrypt communication that goes over the wire.
         * Eg. EMail, Chat...
         */
        COMMUNICATIONS,
        /**
         * The stream will encrypt data that is stored on disk.
         * Eg. Encrypted backup...
         */
        STORAGE,
        /**
         * The stream will use keys with either flags to encrypt the data.
         */
        STORAGE_AND_COMMUNICATIONS
    }

    private static final Logger LOGGER = Logger.getLogger(EncryptionStream2.class.getName());
    private static final Level LEVEL = Level.FINE;

    private static final int BUFFER_SIZE = 1 << 8;

    private final List<EncryptionMethod> encryptionMethods = new ArrayList<>();
    private final List<SignatureMethod> signatureMethods = new ArrayList<>();
    private final SymmetricKeyAlgorithm symmetricKeyAlgorithm;
    private final CompressionAlgorithm compressionAlgorithm;
    private final boolean asciiArmor;

    private final OpenPgpMetadata.Builder resultBuilder = OpenPgpMetadata.getBuilder();

    private Map<SignatureMethod, PGPSignatureGenerator> signatureGenerators = new ConcurrentHashMap<>();
    private boolean closed = false;

    OutputStream outermostStream = null;

    private ArmoredOutputStream armorOutputStream = null;
    private OutputStream publicKeyEncryptedStream = null;

    private PGPCompressedDataGenerator compressedDataGenerator;
    private BCPGOutputStream basicCompressionStream;

    private PGPLiteralDataGenerator literalDataGenerator;
    private OutputStream literalDataStream;

    public EncryptionStream2(OutputStream outputStream,
                             List<EncryptionMethod> encryptionMethods,
                             List<SignatureMethod> signatureMethods,
                             CompressionAlgorithm compressionAlgorithm,
                             SymmetricKeyAlgorithm symmetricKeyAlgorithm,
                             boolean asciiArmor)
            throws IOException, PGPException {
        this.outermostStream = outputStream;
        this.asciiArmor = asciiArmor;
        this.encryptionMethods.addAll(encryptionMethods);
        this.signatureMethods.addAll(signatureMethods);
        this.compressionAlgorithm = compressionAlgorithm;
        this.symmetricKeyAlgorithm = symmetricKeyAlgorithm;

        prepareArmor();
        prepareEncryption();
        prepareSigning();
        prepareCompression();
        prepareOnePassSignatures();
        prepareLiteralDataProcessing();
        prepareResultBuilder();
    }

    private void prepareArmor() {
        if (!asciiArmor) {
            LOGGER.log(LEVEL, "Encryption output will be binary");
            return;
        }

        LOGGER.log(LEVEL, "Wrap encryption output in ASCII armor");
        armorOutputStream = ArmoredOutputStreamFactory.get(outermostStream);
        outermostStream = armorOutputStream;
    }

    private void prepareEncryption() throws IOException, PGPException {
        if (encryptionMethods.isEmpty()) {
            return;
        }

        PGPDataEncryptorBuilder dataEncryptorBuilder = ImplementationFactory.getInstance()
                .getPGPDataEncryptorBuilder(symmetricKeyAlgorithm);
        // TODO: Simplify once https://github.com/bcgit/bc-java/pull/859 is merged
        if (dataEncryptorBuilder instanceof BcPGPDataEncryptorBuilder) {
            ((BcPGPDataEncryptorBuilder) dataEncryptorBuilder).setWithIntegrityPacket(true);
        } else if (dataEncryptorBuilder instanceof JcePGPDataEncryptorBuilder) {
            ((JcePGPDataEncryptorBuilder) dataEncryptorBuilder).setWithIntegrityPacket(true);
        }

        PGPEncryptedDataGenerator encryptedDataGenerator = new PGPEncryptedDataGenerator(dataEncryptorBuilder);
        for (EncryptionMethod encryptionMethod : encryptionMethods) {
            encryptedDataGenerator.addMethod(encryptionMethod.getEncryptionMethodGenerator());
        }

        publicKeyEncryptedStream = encryptedDataGenerator.open(outermostStream, new byte[BUFFER_SIZE]);
        outermostStream = publicKeyEncryptedStream;
    }

    private void prepareSigning() throws PGPException {
        if (signatureMethods.isEmpty()) {
            return;
        }

        for (SignatureMethod signatureMethod : signatureMethods) {
            PGPSignatureGenerator signatureGenerator = signatureMethod.initializeSignatureGenerator(SignatureType.BINARY_DOCUMENT);
            signatureGenerators.put(signatureMethod, signatureGenerator);
        }
    }

    private void prepareCompression() throws IOException {
        compressedDataGenerator = new PGPCompressedDataGenerator(
            compressionAlgorithm.getAlgorithmId());
        if (compressionAlgorithm == CompressionAlgorithm.UNCOMPRESSED) {
            return;
        }

        LOGGER.log(LEVEL, "Compress using " + compressionAlgorithm);
        basicCompressionStream = new BCPGOutputStream(compressedDataGenerator.open(outermostStream));
        outermostStream = basicCompressionStream;
    }

    private void prepareOnePassSignatures() throws IOException, PGPException {
        for (SignatureMethod signatureMethod : signatureMethods) {
            PGPSignatureGenerator signatureGenerator = signatureGenerators.get(signatureMethod);
            signatureGenerator.generateOnePassVersion(false).encode(outermostStream);
        }
    }

    private void prepareLiteralDataProcessing() throws IOException {
        literalDataGenerator = new PGPLiteralDataGenerator();
        literalDataStream = literalDataGenerator.open(outermostStream,
                PGPLiteralData.BINARY, PGPLiteralData.CONSOLE, new Date(), new byte[BUFFER_SIZE]);
        outermostStream = literalDataStream;
    }

    private void prepareResultBuilder() {
        for (EncryptionMethod encryptionMethod : encryptionMethods) {
            if (encryptionMethod instanceof EncryptionMethod.ToPublicKey) {
                resultBuilder.addRecipientKeyId(((EncryptionMethod.ToPublicKey) encryptionMethod).getKey().getKeyID());
            }
        }
        resultBuilder.setSymmetricKeyAlgorithm(symmetricKeyAlgorithm);
        resultBuilder.setCompressionAlgorithm(compressionAlgorithm);
    }

    @Override
    public void write(int data) throws IOException {
        outermostStream.write(data);

        for (SignatureMethod signatureMethod : signatureMethods) {
            PGPSignatureGenerator signatureGenerator = signatureGenerators.get(signatureMethod);
            byte asByte = (byte) (data & 0xff);
            signatureGenerator.update(asByte);
        }
    }

    @Override
    public void write(byte[] buffer) throws IOException {
        write(buffer, 0, buffer.length);
    }


    @Override
    public void write(byte[] buffer, int off, int len) throws IOException {
        outermostStream.write(buffer, 0, len);
        for (SignatureMethod signatureMethod : signatureMethods) {
            PGPSignatureGenerator signatureGenerator = signatureGenerators.get(signatureMethod);
            signatureGenerator.update(buffer, 0, len);
        }
    }

    @Override
    public void flush() throws IOException {
        outermostStream.flush();
    }

    @Override
    public void close() throws IOException {
        if (closed) {
            return;
        }

        // Literal Data
        literalDataStream.flush();
        literalDataStream.close();
        literalDataGenerator.close();

        writeSignatures();

        // Compressed Data
        compressedDataGenerator.close();

        // Public Key Encryption
        if (publicKeyEncryptedStream != null) {
            publicKeyEncryptedStream.flush();
            publicKeyEncryptedStream.close();
        }

        // Armor
        if (armorOutputStream != null) {
            armorOutputStream.flush();
            armorOutputStream.close();
        }
        closed = true;
    }

    private void writeSignatures() throws IOException {
        for (SignatureMethod signatureMethod : signatureMethods) {
            PGPSignatureGenerator signatureGenerator = signatureGenerators.get(signatureMethod);

            try {
                PGPSignature signature = signatureGenerator.generate();
                if (signatureMethod.isInlineSignature()) {
                    signature.encode(outermostStream);
                } else {
                    resultBuilder.addDetachedSignature(new DetachedSignature(signature, signatureMethod.getFingerprint()));
                }
            } catch (PGPException e) {
                throw new IOException(e);
            }
        }
    }

    public OpenPgpMetadata getResult() {
        if (!closed) {
            throw new IllegalStateException("EncryptionStream must be closed before accessing the Result.");
        }
        return resultBuilder.build();
    }
}
