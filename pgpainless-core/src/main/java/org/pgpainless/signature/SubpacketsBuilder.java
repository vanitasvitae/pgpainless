package org.pgpainless.signature;

import java.io.IOException;
import java.net.URI;
import java.util.Date;
import java.util.List;
import java.util.Set;
import javax.annotation.Nonnull;

import org.bouncycastle.openpgp.PGPSignature;
import org.pgpainless.algorithm.CompressionAlgorithm;
import org.pgpainless.algorithm.Feature;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.algorithm.KeyServerPreferences;
import org.pgpainless.algorithm.PublicKeyAlgorithm;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.key.OpenPgpV4Fingerprint;
import org.pgpainless.key.util.RevocationAttributes;

public abstract class SubpacketsBuilder {

    enum Area {
        hashed,
        unhashed
    }

    interface BaseSignature<B extends BaseSignature<B>> {

        B setSignatureCreationTime(@Nonnull Date creationTime, @Nonnull Area area, boolean critical);

        B setIssuer(long keyId, @Nonnull Area area, boolean critical);

        B setSignatureExpirationTime(long secondsUntilExpiration, @Nonnull Area area, boolean critical);

        B setRevocable(boolean revocable, @Nonnull Area area, boolean critical);

        B setTrustSignature(int level, int amount, @Nonnull Area area, boolean critical);

        B setRegularExpression(@Nonnull String regex, @Nonnull Area area, boolean critical);

        B addNotationData(@Nonnull String notationName, @Nonnull String notationValue, @Nonnull Area area, boolean critical);

        B setPolicyURI(@Nonnull URI policyURI, @Nonnull Area area, boolean critical);

        B setPreferredKeyServer(@Nonnull URI keyServerURI, @Nonnull Area area, boolean critical);

        B setKeyFlags(@Nonnull Set<KeyFlag> keyFlags, @Nonnull Area area, boolean critical);

        B setSignersUserId(@Nonnull String signerUserId, @Nonnull Area area, boolean critical);

        B setSignatureTarget(@Nonnull PublicKeyAlgorithm publicKeyAlgorithm,
                                             @Nonnull HashAlgorithm hashAlgorithm,
                                             @Nonnull byte[] hashData,
                                             @Nonnull Area area, boolean critical);

        B addEmbeddedSignature(@Nonnull PGPSignature embeddedSignature, @Nonnull Area area, boolean critical) throws IOException;
    }

    interface CertificationSignature<B extends CertificationSignature<B>> extends BaseSignature<B> {

        B setExportable(boolean exportable, @Nonnull Area area, boolean critical);

    }

    interface RevocationSignature<B extends RevocationSignature<B>> extends BaseSignature<B> {

        B setRevocationReason(@Nonnull RevocationAttributes revocationReason, @Nonnull Area area, boolean critical);

    }

    interface SelfSignature<B extends SelfSignature<B>> extends CertificationSignature<B> {

        /**
         * Set the keys expiration time.
         * 0 denotes no expiration, while any non-negative number denotes the number of seconds that the signed
         * key is valid for after its creation date.
         *
         * @see <a href="https://datatracker.ietf.org/doc/html/rfc4880#section-5.2.3.6">Key Expiration Time</a>
         *
         * @param secondsUntilExpiration number of seconds that the key is valid for since it has been created
         * @param area subpackets area
         * @param critical whether the subpacket is critical
         * @return builder
         */
        B setKeyExpirationTime(long secondsUntilExpiration, @Nonnull Area area, boolean critical);

        /**
         * Set the keys preferred symmetric encryption algorithms.
         *
         * @see <a href="https://datatracker.ietf.org/doc/html/rfc4880#section-5.2.3.7">Preferred Symmetric Algorithms</a>
         *
         * @param algorithms Sorted (high to low priority) list of preferred algorithms
         * @param area subpackets area
         * @param critical whether the subpacket is critical
         * @return builder
         */
        B setPreferredSymmetricAlgorithms(@Nonnull List<SymmetricKeyAlgorithm> algorithms, @Nonnull Area area, boolean critical);

        /**
         * Set the keys preferred hash algorithms.
         *
         * @see <a href="https://datatracker.ietf.org/doc/html/rfc4880#section-5.2.3.8">Preferred Hash Algorithms</a>
         *
         * @param algorithms Sorted (high to low priority) list of preferred hash algorithms
         * @param area subpackets area
         * @param critical whether the subpacket is critical
         * @return builder
         */
        B setPreferredHashAlgorithms(@Nonnull List<HashAlgorithm> algorithms, @Nonnull Area area, boolean critical);

        /**
         * Set the keys preferred compression algorithms.
         *
         * @see <a href="https://datatracker.ietf.org/doc/html/rfc4880#section-5.2.3.9">Preferred Compression Algorithms</a>
         *
         * @param algorithms Sorted (high to low priority) list of preferred compression algorithms
         * @param area subpackets area
         * @param critical whether the subpacket is critical
         * @return builder
         */
        B setPreferredCompressionAlgorithms(@Nonnull List<CompressionAlgorithm> algorithms, @Nonnull Area area, boolean critical);

        B setRevocationKey(@Nonnull PublicKeyAlgorithm algorithm, @Nonnull OpenPgpV4Fingerprint fingerprint, @Nonnull Area area, boolean critical);

        B setKeyServerPreferences(@Nonnull KeyServerPreferences preferences, @Nonnull Area area, boolean critical);

        B setPrimaryUserId(boolean isPrimary, @Nonnull Area area, boolean critical);

        B setFeatures(@Nonnull Set<Feature> features, @Nonnull Area area, boolean critical);
    }
}
