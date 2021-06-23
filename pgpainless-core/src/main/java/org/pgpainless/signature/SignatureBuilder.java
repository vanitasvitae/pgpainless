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
package org.pgpainless.signature;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.Charset;
import java.util.Date;
import java.util.List;
import java.util.Set;
import javax.annotation.Nonnull;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector;
import org.pgpainless.algorithm.CompressionAlgorithm;
import org.pgpainless.algorithm.Feature;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.algorithm.KeyServerPreferences;
import org.pgpainless.algorithm.PublicKeyAlgorithm;
import org.pgpainless.algorithm.SignatureType;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.exception.NotYetImplementedException;
import org.pgpainless.key.OpenPgpV4Fingerprint;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.key.protection.UnlockSecretKey;
import org.pgpainless.key.util.RevocationAttributes;

/**
 * Opinionated SignatureBuilder.
 */
public class SignatureBuilder {
    protected final SignatureType signatureType;
    protected final PGPSecretKey signingKey;
    protected Date signatureCreationTime = new Date();
    protected final BCBasedSubpacketsBuilder builder;
    protected final SignatureGeneratorExecutor executor;

    public SignatureBuilder(@Nonnull PGPSecretKey signingKey, @Nonnull SignatureType type, SignatureGeneratorExecutor executor) {
        this.signatureType = type;
        this.signingKey = signingKey;

        this.builder = new BCBasedSubpacketsBuilder();
        this.executor = executor;
    }

    public SignatureBuilder setSignatureCreationTime(@Nonnull Date creationTime) {
        this.signatureCreationTime = creationTime;
        return this;
    }

    public SignatureBuilder setSignersUserId(String signerUserId) {
        // Place the signerUserId in the hashed area, since it is a non-self-validating datum
        builder.setSignersUserId(signerUserId, BCBasedSubpacketsBuilder.Area.hashed, false);
        return this;
    }

    public PGPSignature build(SecretKeyRingProtector protector) throws PGPException {
        PGPSignatureGenerator generator = new PGPSignatureGenerator(
                SignatureUtils.getPgpContentSignerBuilderForKey(signingKey.getPublicKey())
        );

        generator.setHashedSubpackets(builder.hashedSubpackets.generate());
        generator.setUnhashedSubpackets(builder.unhashedSubpackets.generate());

        PGPPrivateKey privateKey = UnlockSecretKey.unlockSecretKey(signingKey, protector);
        generator.init(signatureType.getCode(), privateKey);

        return executor.execute(generator);
    }

    public static class SelfSignatureBuilder extends SignatureBuilder {

        public SelfSignatureBuilder(PGPSecretKey signingKey, SignatureType type, SignatureGeneratorExecutor executor) {
            super(signingKey, type, executor);
        }

        /**
         *
         * @param revocationKey
         * @return
         */
        public SelfSignatureBuilder setRevocationKey(PGPPublicKey revocationKey) {
            builder.setRevocationKey(
                    PublicKeyAlgorithm.fromId(revocationKey.getAlgorithm()),
                    new OpenPgpV4Fingerprint(revocationKey),
                    BCBasedSubpacketsBuilder.Area.hashed,
                    true);
            return this;
        }

        /**
         *
         * TODO: This is not yet implemented in BC, so expect a {@link NotYetImplementedException} to be thrown.
         * @param preferences
         * @return
         */
        public SelfSignatureBuilder setKeyServerPreferences(KeyServerPreferences preferences) {
            builder.setKeyServerPreferences(preferences, BCBasedSubpacketsBuilder.Area.hashed, false);
            return this;
        }

        public SelfSignatureBuilder addEmbeddedSignature(PGPSignature signature, boolean critical)
                throws IOException {
            builder.addEmbeddedSignature(signature, BCBasedSubpacketsBuilder.Area.hashed, critical);
            return this;
        }
    }

    public static class BCSignatureBuilder implements SubpacketsBuilder.BaseSignature<BCSignatureBuilder> {

        @Override
        public BCSignatureBuilder setSignatureCreationTime(@Nonnull Date creationTime, @Nonnull SubpacketsBuilder.Area area, boolean critical) {
            return null;
        }

        @Override
        public BCSignatureBuilder setIssuer(long keyId, @Nonnull SubpacketsBuilder.Area area, boolean critical) {
            return null;
        }

        @Override
        public BCSignatureBuilder setSignatureExpirationTime(long secondsUntilExpiration, @Nonnull SubpacketsBuilder.Area area, boolean critical) {
            return null;
        }

        @Override
        public BCSignatureBuilder setRevocable(boolean revocable, @Nonnull SubpacketsBuilder.Area area, boolean critical) {
            return null;
        }

        @Override
        public BCSignatureBuilder setTrustSignature(int level, int amount, @Nonnull SubpacketsBuilder.Area area, boolean critical) {
            return null;
        }

        @Override
        public BCSignatureBuilder setRegularExpression(@Nonnull String regex, @Nonnull SubpacketsBuilder.Area area, boolean critical) {
            return null;
        }

        @Override
        public BCSignatureBuilder addNotationData(@Nonnull String notationName, @Nonnull String notationValue, @Nonnull SubpacketsBuilder.Area area, boolean critical) {
            return null;
        }

        @Override
        public BCSignatureBuilder setPolicyURI(@Nonnull URI policyURI, @Nonnull SubpacketsBuilder.Area area, boolean critical) {
            return null;
        }

        @Override
        public BCSignatureBuilder setPreferredKeyServer(@Nonnull URI keyServerURI, @Nonnull SubpacketsBuilder.Area area, boolean critical) {
            return null;
        }

        @Override
        public BCSignatureBuilder setKeyFlags(@Nonnull Set<KeyFlag> keyFlags, @Nonnull SubpacketsBuilder.Area area, boolean critical) {
            return null;
        }

        @Override
        public BCSignatureBuilder setSignersUserId(@Nonnull String signerUserId, @Nonnull SubpacketsBuilder.Area area, boolean critical) {
            return null;
        }

        @Override
        public BCSignatureBuilder setSignatureTarget(@Nonnull PublicKeyAlgorithm publicKeyAlgorithm, @Nonnull HashAlgorithm hashAlgorithm, @Nonnull byte[] hashData, @Nonnull SubpacketsBuilder.Area area, boolean critical) {
            return null;
        }

        @Override
        public BCSignatureBuilder addEmbeddedSignature(@Nonnull PGPSignature embeddedSignature, @Nonnull SubpacketsBuilder.Area area, boolean critical) throws IOException {
            return null;
        }
    }

    public static class BCSelfSignatureBuilder implements SubpacketsBuilder.SelfSignature<BCSelfSignatureBuilder> {

        @Override
        public BCSelfSignatureBuilder setSignatureCreationTime(@Nonnull Date creationTime, @Nonnull SubpacketsBuilder.Area area, boolean critical) {
            return null;
        }

        @Override
        public BCSelfSignatureBuilder setIssuer(long keyId, @Nonnull SubpacketsBuilder.Area area, boolean critical) {
            return null;
        }

        @Override
        public BCSelfSignatureBuilder setSignatureExpirationTime(long secondsUntilExpiration, @Nonnull SubpacketsBuilder.Area area, boolean critical) {
            return null;
        }

        @Override
        public BCSelfSignatureBuilder setRevocable(boolean revocable, @Nonnull SubpacketsBuilder.Area area, boolean critical) {
            return null;
        }

        @Override
        public BCSelfSignatureBuilder setTrustSignature(int level, int amount, @Nonnull SubpacketsBuilder.Area area, boolean critical) {
            return null;
        }

        @Override
        public BCSelfSignatureBuilder setRegularExpression(@Nonnull String regex, @Nonnull SubpacketsBuilder.Area area, boolean critical) {
            return null;
        }

        @Override
        public BCSelfSignatureBuilder addNotationData(@Nonnull String notationName, @Nonnull String notationValue, @Nonnull SubpacketsBuilder.Area area, boolean critical) {
            return null;
        }

        @Override
        public BCSelfSignatureBuilder setPolicyURI(@Nonnull URI policyURI, @Nonnull SubpacketsBuilder.Area area, boolean critical) {
            return null;
        }

        @Override
        public BCSelfSignatureBuilder setPreferredKeyServer(@Nonnull URI keyServerURI, @Nonnull SubpacketsBuilder.Area area, boolean critical) {
            return null;
        }

        @Override
        public BCSelfSignatureBuilder setKeyFlags(@Nonnull Set<KeyFlag> keyFlags, @Nonnull SubpacketsBuilder.Area area, boolean critical) {
            return null;
        }

        @Override
        public BCSelfSignatureBuilder setSignersUserId(@Nonnull String signerUserId, @Nonnull SubpacketsBuilder.Area area, boolean critical) {
            return null;
        }

        @Override
        public BCSelfSignatureBuilder setSignatureTarget(@Nonnull PublicKeyAlgorithm publicKeyAlgorithm, @Nonnull HashAlgorithm hashAlgorithm, @Nonnull byte[] hashData, @Nonnull SubpacketsBuilder.Area area, boolean critical) {
            return null;
        }

        @Override
        public BCSelfSignatureBuilder addEmbeddedSignature(@Nonnull PGPSignature embeddedSignature, @Nonnull SubpacketsBuilder.Area area, boolean critical) throws IOException {
            return null;
        }

        @Override
        public BCSelfSignatureBuilder setExportable(boolean exportable, @Nonnull SubpacketsBuilder.Area area, boolean critical) {
            return null;
        }

        @Override
        public BCSelfSignatureBuilder setKeyExpirationTime(long secondsUntilExpiration, @Nonnull SubpacketsBuilder.Area area, boolean critical) {
            return null;
        }

        @Override
        public BCSelfSignatureBuilder setPreferredSymmetricAlgorithms(@Nonnull List<SymmetricKeyAlgorithm> algorithms, @Nonnull SubpacketsBuilder.Area area, boolean critical) {
            return null;
        }

        @Override
        public BCSelfSignatureBuilder setPreferredHashAlgorithms(@Nonnull List<HashAlgorithm> algorithms, @Nonnull SubpacketsBuilder.Area area, boolean critical) {
            return null;
        }

        @Override
        public BCSelfSignatureBuilder setPreferredCompressionAlgorithms(@Nonnull List<CompressionAlgorithm> algorithms, @Nonnull SubpacketsBuilder.Area area, boolean critical) {
            return null;
        }

        @Override
        public BCSelfSignatureBuilder setRevocationKey(@Nonnull PublicKeyAlgorithm algorithm, @Nonnull OpenPgpV4Fingerprint fingerprint, @Nonnull SubpacketsBuilder.Area area, boolean critical) {
            return null;
        }

        @Override
        public BCSelfSignatureBuilder setKeyServerPreferences(@Nonnull KeyServerPreferences preferences, @Nonnull SubpacketsBuilder.Area area, boolean critical) {
            return null;
        }

        @Override
        public BCSelfSignatureBuilder setPrimaryUserId(boolean isPrimary, @Nonnull SubpacketsBuilder.Area area, boolean critical) {
            return null;
        }

        @Override
        public BCSelfSignatureBuilder setFeatures(@Nonnull Set<Feature> features, @Nonnull SubpacketsBuilder.Area area, boolean critical) {
            return null;
        }
    }

    public static class BCBasedSubpacketsBuilder implements SubpacketsBuilder {

        private PGPSignatureSubpacketGenerator hashedSubpackets;
        private PGPSignatureSubpacketGenerator unhashedSubpackets;

        public BCBasedSubpacketsBuilder() {
            this.hashedSubpackets = new PGPSignatureSubpacketGenerator();
            this.unhashedSubpackets = new PGPSignatureSubpacketGenerator();
        }

        private @Nonnull PGPSignatureSubpacketGenerator getSubpackets(@Nonnull Area area) {
            return (area == Area.hashed ? hashedSubpackets : unhashedSubpackets);
        }

        @Override
        public BCBasedSubpacketsBuilder setSignatureCreationTime(@Nonnull Date creationTime, @Nonnull Area area, boolean critical) {
            getSubpackets(area).setSignatureCreationTime(critical, creationTime);
            return this;
        }

        @Override
        public BCBasedSubpacketsBuilder setIssuer(long keyId, @Nonnull Area area, boolean critical) {
            getSubpackets(area).setIssuerKeyID(critical, keyId);
            return this;
        }

        @Override
        public BCBasedSubpacketsBuilder setKeyExpirationTime(long secondsUntilExpiration, @Nonnull Area area, boolean critical) {
            getSubpackets(area).setKeyExpirationTime(critical, secondsUntilExpiration);
            return this;
        }

        @Override
        public BCBasedSubpacketsBuilder setPreferredSymmetricAlgorithms(@Nonnull List<SymmetricKeyAlgorithm> algorithms, @Nonnull Area area, boolean critical) {
            int[] algorithmCodes = new int[algorithms.size()];
            for (int i = 0, algorithmsSize = algorithms.size(); i < algorithmsSize; i++) {
                algorithmCodes[i] = algorithms.get(i).getAlgorithmId();
            }

            getSubpackets(area).setPreferredSymmetricAlgorithms(critical, algorithmCodes);
            return this;
        }

        @Override
        public BCBasedSubpacketsBuilder setPreferredHashAlgorithms(@Nonnull List<HashAlgorithm> algorithms, @Nonnull Area area, boolean critical) {
            int[] algorithmCodes = new int[algorithms.size()];
            for (int i = 0, algorithmsSize = algorithms.size(); i < algorithmsSize; i++) {
                algorithmCodes[i] = algorithms.get(i).getAlgorithmId();
            }

            getSubpackets(area).setPreferredHashAlgorithms(critical, algorithmCodes);
            return this;
        }

        @Override
        public BCBasedSubpacketsBuilder setPreferredCompressionAlgorithms(@Nonnull List<CompressionAlgorithm> algorithms, @Nonnull Area area, boolean critical) {
            int[] algorithmsCodes = new int[algorithms.size()];
            for (int i = 0, algorithmsSize = algorithms.size(); i < algorithmsSize; i++) {
                algorithmsCodes[i] = algorithms.get(i).getAlgorithmId();
            }

            getSubpackets(area).setPreferredCompressionAlgorithms(critical, algorithmsCodes);
            return this;
        }

        @Override
        public BCBasedSubpacketsBuilder setSignatureExpirationTime(long secondsUntilExpiration, @Nonnull Area area, boolean critical) {
            getSubpackets(area).setSignatureExpirationTime(critical, secondsUntilExpiration);
            return this;
        }

        @Override
        public BCBasedSubpacketsBuilder setExportable(boolean exportable, @Nonnull Area area, boolean critical) {
            getSubpackets(area).setExportable(critical, exportable);
            return this;
        }

        @Override
        public BCBasedSubpacketsBuilder setRevocable(boolean revocable, @Nonnull Area area, boolean critical) {
            getSubpackets(area).setRevocable(critical, revocable);
            return this;
        }

        @Override
        public BCBasedSubpacketsBuilder setTrustSignature(int level, int amount, @Nonnull Area area, boolean critical) {
            if (level < 0 || level > 255) {
                throw new IllegalArgumentException("Trust level must be a positive number in the range of 0 <= level <= 255");
            }
            if (amount < 0 || amount > 255) {
                throw new IllegalArgumentException("Trust amount must be a positibe number in the range of 0 <= amount <= 255");
            }
            getSubpackets(area).setTrust(critical, level, amount);
            return this;
        }

        @Override
        public BCBasedSubpacketsBuilder setRegularExpression(@Nonnull String regex, @Nonnull Area area, boolean critical) {
            throw new NotYetImplementedException();
        }

        @Override
        public BCBasedSubpacketsBuilder setRevocationKey(@Nonnull PublicKeyAlgorithm algorithm, @Nonnull OpenPgpV4Fingerprint fingerprint, @Nonnull Area area, boolean critical) {
            getSubpackets(area).addRevocationKey(critical, algorithm.getAlgorithmId(), fingerprint.toString().getBytes(Charset.forName("UTF-8")));
            return this;
        }

        @Override
        public BCBasedSubpacketsBuilder addNotationData(@Nonnull String notationName, @Nonnull String notationValue, @Nonnull Area area, boolean critical) {
            getSubpackets(area).addNotationData(critical, true, notationName, notationValue);
            return this;
        }

        @Override
        public BCBasedSubpacketsBuilder setKeyServerPreferences(@Nonnull KeyServerPreferences preferences, @Nonnull Area area, boolean critical) {
            throw new NotYetImplementedException();
        }

        @Override
        public BCBasedSubpacketsBuilder setPreferredKeyServer(@Nonnull URI keyServerURI, @Nonnull Area area, boolean critical) {
            throw new NotYetImplementedException();
        }

        @Override
        public BCBasedSubpacketsBuilder setPrimaryUserId(boolean isPrimary, @Nonnull Area area, boolean critical) {
            getSubpackets(area).setPrimaryUserID(critical, isPrimary);
            return this;
        }

        @Override
        public BCBasedSubpacketsBuilder setPolicyURI(@Nonnull URI policyURI, @Nonnull Area area, boolean critical) {
            throw new NotYetImplementedException();
        }

        @Override
        public BCBasedSubpacketsBuilder setKeyFlags(@Nonnull Set<KeyFlag> keyFlags, @Nonnull Area area, boolean critical) {
            int mask = KeyFlag.toBitmask(keyFlags);
            getSubpackets(area).setKeyFlags(critical, mask);
            return this;
        }

        @Override
        public BCBasedSubpacketsBuilder setSignersUserId(@Nonnull String signerUserId, @Nonnull Area area, boolean critical) {
            getSubpackets(area).addSignerUserID(critical, signerUserId);
            return this;
        }

        @Override
        public BCBasedSubpacketsBuilder setRevocationReason(@Nonnull RevocationAttributes revocationReason, @Nonnull Area area, boolean critical) {
            getSubpackets(area).setRevocationReason(critical, revocationReason.getReason().code(), revocationReason.getDescription());
            return this;
        }

        @Override
        public BCBasedSubpacketsBuilder setFeatures(@Nonnull Set<Feature> features, @Nonnull Area area, boolean critical) {
            for (Feature feature : features) {
                getSubpackets(area).setFeature(critical, feature.getFeatureId());
            }
            return this;
        }

        @Override
        public BCBasedSubpacketsBuilder setSignatureTarget(@Nonnull PublicKeyAlgorithm publicKeyAlgorithm,
                                                           @Nonnull HashAlgorithm hashAlgorithm,
                                                           @Nonnull byte[] hashData,
                                                           @Nonnull Area area, boolean critical) {
            getSubpackets(area).setSignatureTarget(critical, publicKeyAlgorithm.getAlgorithmId(), hashAlgorithm.getAlgorithmId(), hashData);
            return this;
        }

        @Override
        public BCBasedSubpacketsBuilder addEmbeddedSignature(@Nonnull PGPSignature embeddedSignature, @Nonnull Area area, boolean critical)
                throws IOException {
            getSubpackets(area).addEmbeddedSignature(critical, embeddedSignature);
            return this;
        }

        public PGPSignatureSubpacketVector getHashedSubpackets() {
            return hashedSubpackets.generate();
        }

        public PGPSignatureSubpacketVector getUnhashedSubpackets() {
            return unhashedSubpackets.generate();
        }
    }

    public interface SignatureGeneratorExecutor {
        PGPSignature execute(PGPSignatureGenerator generator) throws PGPException;
    }
}
