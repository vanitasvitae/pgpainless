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
    protected final LowLevelSignatureBuilder builder;

    protected SignatureBuilder(@Nonnull PGPSecretKey signingKey, @Nonnull SignatureType type) {
        this.signatureType = type;
        this.signingKey = signingKey;

        this.builder = new LowLevelSignatureBuilder();
    }

    public SignatureBuilder setSignatureCreationTime(@Nonnull Date creationTime) {
        this.signatureCreationTime = creationTime;
        return this;
    }

    public SignatureBuilder setSignersUserId(String signerUserId) {
        // Place the signerUserId in the hashed area, since it is a non-self-validating datum
        builder.setSignersUserId(signerUserId, LowLevelSignatureBuilder.Area.hashed, false);
        return this;
    }

    private void prepareDefaultSubpackets() {
        builder.setSignatureCreationTime(signatureCreationTime, LowLevelSignatureBuilder.Area.hashed, true);
    }

    private void addSubpacketsToSignatureGenerator(PGPSignatureGenerator generator) {
        PGPSignatureSubpacketVector hashed = builder.hashedSubpackets.generate();
        generator.setHashedSubpackets(hashed);
        PGPSignatureSubpacketVector unhashed = builder.unhashedSubpackets.generate();
        generator.setUnhashedSubpackets(unhashed);
    }

    public PGPSignatureGenerator createSignatureGenerator(SecretKeyRingProtector protector) throws PGPException {
        builder.setSignatureCreationTime(signatureCreationTime, LowLevelSignatureBuilder.Area.hashed, true);

        PGPSignatureGenerator signatureGenerator = SignatureUtils.getSignatureGeneratorFor(signingKey);
        addSubpacketsToSignatureGenerator(signatureGenerator);

        PGPPrivateKey privateKey = UnlockSecretKey.unlockSecretKey(signingKey, protector);
        signatureGenerator.init(signatureType.getCode(), privateKey);
    }

    public class SelfSignatureBuilder extends SignatureBuilder {

        private SelfSignatureBuilder(PGPSecretKey signingKey, SignatureType type) {
            super(signingKey, type);
        }

        public SelfSignatureBuilder setRevocationKey(PGPPublicKey revocationKey) {
            builder.setRevocationKey(
                    PublicKeyAlgorithm.fromId(revocationKey.getAlgorithm()),
                    new OpenPgpV4Fingerprint(revocationKey),
                    LowLevelSignatureBuilder.Area.hashed,
                    true);
            return this;
        }

        public SelfSignatureBuilder setKeyServerPreferences(KeyServerPreferences preferences) {
            builder.setKeyServerPreferences(preferences, LowLevelSignatureBuilder.Area.hashed, false);
            return this;
        }
    }

    public static class LowLevelSignatureBuilder {

        public enum Area {
            hashed,
            unhashed
        }

        private PGPSignatureSubpacketGenerator hashedSubpackets;
        private PGPSignatureSubpacketGenerator unhashedSubpackets;

        public LowLevelSignatureBuilder() {
            this.hashedSubpackets = new PGPSignatureSubpacketGenerator();
            this.unhashedSubpackets = new PGPSignatureSubpacketGenerator();
        }

        private @Nonnull PGPSignatureSubpacketGenerator getSubpackets(@Nonnull Area area) {
            return (area == Area.hashed ? hashedSubpackets : unhashedSubpackets);
        }

        public LowLevelSignatureBuilder setSignatureCreationTime(@Nonnull Date creationTime, @Nonnull Area area, boolean critical) {
            getSubpackets(area).setSignatureCreationTime(critical, creationTime);
            return this;
        }

        public LowLevelSignatureBuilder setIssuer(long keyId, @Nonnull Area area, boolean critical) {
            getSubpackets(area).setIssuerKeyID(critical, keyId);
            return this;
        }

        public LowLevelSignatureBuilder setKeyExpirationTime(long secondsUntilExpiration, @Nonnull Area area, boolean critical) {
            getSubpackets(area).setKeyExpirationTime(critical, secondsUntilExpiration);
            return this;
        }

        public LowLevelSignatureBuilder setPreferredSymmetricAlgorithms(@Nonnull List<SymmetricKeyAlgorithm> algorithms, @Nonnull Area area, boolean critical) {
            int[] algorithmCodes = new int[algorithms.size()];
            for (int i = 0, algorithmsSize = algorithms.size(); i < algorithmsSize; i++) {
                algorithmCodes[i] = algorithms.get(i).getAlgorithmId();
            }

            getSubpackets(area).setPreferredSymmetricAlgorithms(critical, algorithmCodes);
            return this;
        }

        public LowLevelSignatureBuilder setPreferredHashAlgorithms(@Nonnull List<HashAlgorithm> algorithms, @Nonnull Area area, boolean critical) {
            int[] algorithmCodes = new int[algorithms.size()];
            for (int i = 0, algorithmsSize = algorithms.size(); i < algorithmsSize; i++) {
                algorithmCodes[i] = algorithms.get(i).getAlgorithmId();
            }

            getSubpackets(area).setPreferredHashAlgorithms(critical, algorithmCodes);
            return this;
        }

        public LowLevelSignatureBuilder setPreferredCompressionAlgorithms(@Nonnull List<CompressionAlgorithm> algorithms, @Nonnull Area area, boolean critical) {
            int[] algorithmsCodes = new int[algorithms.size()];
            for (int i = 0, algorithmsSize = algorithms.size(); i < algorithmsSize; i++) {
                algorithmsCodes[i] = algorithms.get(i).getAlgorithmId();
            }

            getSubpackets(area).setPreferredCompressionAlgorithms(critical, algorithmsCodes);
            return this;
        }

        public LowLevelSignatureBuilder setSignatureExpirationTime(long secondsUntilExpiration, @Nonnull Area area, boolean critical) {
            getSubpackets(area).setSignatureExpirationTime(critical, secondsUntilExpiration);
            return this;
        }

        public LowLevelSignatureBuilder setExportable(boolean exportable, @Nonnull Area area, boolean critical) {
            getSubpackets(area).setExportable(critical, exportable);
            return this;
        }

        public LowLevelSignatureBuilder setRevocable(boolean revocable, @Nonnull Area area, boolean critical) {
            getSubpackets(area).setRevocable(critical, revocable);
            return this;
        }

        public LowLevelSignatureBuilder setTrustSignature(int level, int amount, @Nonnull Area area, boolean critical) {
            if (level < 0 || level > 255) {
                throw new IllegalArgumentException("Trust level must be a positive number in the range of 0 <= level <= 255");
            }
            if (amount < 0 || amount > 255) {
                throw new IllegalArgumentException("Trust amount must be a positibe number in the range of 0 <= amount <= 255");
            }
            getSubpackets(area).setTrust(critical, level, amount);
            return this;
        }

        public LowLevelSignatureBuilder setRegularExpression(@Nonnull String regex, @Nonnull Area area, boolean critical) {
            throw new NotYetImplementedException();
        }

        public LowLevelSignatureBuilder setRevocationKey(@Nonnull PublicKeyAlgorithm algorithm, @Nonnull OpenPgpV4Fingerprint fingerprint, @Nonnull Area area, boolean critical) {
            getSubpackets(area).addRevocationKey(critical, algorithm.getAlgorithmId(), fingerprint.toString().getBytes(Charset.forName("UTF-8")));
            return this;
        }

        public LowLevelSignatureBuilder addNotationData(@Nonnull String notationName, @Nonnull String notationValue, @Nonnull Area area, boolean critical) {
            getSubpackets(area).addNotationData(critical, true, notationName, notationValue);
            return this;
        }

        public LowLevelSignatureBuilder setKeyServerPreferences(@Nonnull KeyServerPreferences preferences, @Nonnull Area area, boolean critical) {
            throw new NotYetImplementedException();
        }

        public LowLevelSignatureBuilder setPreferredKeyServer(@Nonnull URI keyServerURI, @Nonnull Area area, boolean critical) {
            throw new NotYetImplementedException();
        }

        public LowLevelSignatureBuilder setPrimaryUserId(boolean isPrimary, @Nonnull Area area, boolean critical) {
            getSubpackets(area).setPrimaryUserID(critical, isPrimary);
            return this;
        }

        public LowLevelSignatureBuilder setPolicyURI(@Nonnull URI policyURI, @Nonnull Area area, boolean critical) {
            throw new NotYetImplementedException();
        }

        public LowLevelSignatureBuilder setKeyFlags(@Nonnull Set<KeyFlag> keyFlags, @Nonnull Area area, boolean critical) {
            int mask = KeyFlag.toBitmask(keyFlags);
            getSubpackets(area).setKeyFlags(critical, mask);
            return this;
        }

        public LowLevelSignatureBuilder setSignersUserId(@Nonnull String signerUserId, @Nonnull Area area, boolean critical) {
            getSubpackets(area).addSignerUserID(critical, signerUserId);
            return this;
        }

        public LowLevelSignatureBuilder setRevocationReason(@Nonnull RevocationAttributes revocationReason, @Nonnull Area area, boolean critical) {
            getSubpackets(area).setRevocationReason(critical, revocationReason.getReason().code(), revocationReason.getDescription());
            return this;
        }

        public LowLevelSignatureBuilder setFeatures(@Nonnull Set<Feature> features, @Nonnull Area area, boolean critical) {
            for (Feature feature : features) {
                getSubpackets(area).setFeature(critical, feature.getFeatureId());
            }
            return this;
        }

        public LowLevelSignatureBuilder setSignatureTarget(@Nonnull PublicKeyAlgorithm publicKeyAlgorithm,
                                                           @Nonnull HashAlgorithm hashAlgorithm,
                                                           @Nonnull byte[] hashData,
                                                           @Nonnull Area area, boolean critical) {
            getSubpackets(area).setSignatureTarget(critical, publicKeyAlgorithm.getAlgorithmId(), hashAlgorithm.getAlgorithmId(), hashData);
            return this;
        }

        public LowLevelSignatureBuilder addEmbeddedSignature(@Nonnull PGPSignature embeddedSignature, @Nonnull Area area, boolean critical)
                throws IOException {
            getSubpackets(area).addEmbeddedSignature(critical, embeddedSignature);
            return this;
        }

        public PGPSignature createUserIdCertification(String userId, PGPSecretKey signingKey) {
        }
    }
}
