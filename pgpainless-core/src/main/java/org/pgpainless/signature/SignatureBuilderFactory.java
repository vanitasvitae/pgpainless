package org.pgpainless.signature;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.pgpainless.algorithm.PublicKeyAlgorithm;
import org.pgpainless.algorithm.SignatureType;
import org.pgpainless.key.protection.SecretKeyRingProtector;

public class SignatureBuilderFactory {

    public static SignatureBuilder.SelfSignatureBuilder getBuilderForDirectKeySelfSignature(PGPSecretKeyRing secretKey) {
        return new SignatureBuilder.SelfSignatureBuilder(
                secretKey.getSecretKey(),
                SignatureType.DIRECT_KEY,
                new SignatureBuilder.SignatureGeneratorExecutor() {
                    @Override
                    public PGPSignature execute(PGPSignatureGenerator generator) throws PGPException {
                        return generator.generateCertification(secretKey.getPublicKey());
                    }
                });
    }

    public static SignatureBuilder getBuilderForDirectKeySignatureOnKey(PGPSecretKeyRing secretKey, PGPPublicKey targetKey) {
        return new SignatureBuilder(
                secretKey.getSecretKey(),
                SignatureType.DIRECT_KEY,
                new SignatureBuilder.SignatureGeneratorExecutor() {
                    @Override
                    public PGPSignature execute(PGPSignatureGenerator generator) throws PGPException {
                        return generator.generateCertification(targetKey);
                    }
                });
    }

    public static SignatureBuilder getBuilderForPrimaryKeyBindingSignature(PGPSecretKeyRing secretKey, PGPSecretKey subkey) {
        return new SignatureBuilder(
                subkey,
                SignatureType.PRIMARYKEY_BINDING,
                new SignatureBuilder.SignatureGeneratorExecutor() {
                    @Override
                    public PGPSignature execute(PGPSignatureGenerator generator) throws PGPException {
                        return generator.generateCertification(secretKey.getPublicKey(), subkey.getPublicKey());
                    }
                }
        );
    }

    public static SignatureBuilder getBuilderForSubkeyBindingSignature(PGPSecretKeyRing secretKey, PGPSecretKey subkey, SecretKeyRingProtector subkeyProtector) {
        boolean isSigningKey = PublicKeyAlgorithm.fromId(subkey.getPublicKey().getAlgorithm()).isSigningCapable();
        SignatureBuilder.SelfSignatureBuilder builder = new SignatureBuilder.SelfSignatureBuilder(
                secretKey.getSecretKey(),
                SignatureType.SUBKEY_BINDING,
                new SignatureBuilder.SignatureGeneratorExecutor() {
                    @Override
                    public PGPSignature execute(PGPSignatureGenerator generator) throws PGPException {
                        return generator.generateCertification(secretKey.getPublicKey(), subkey.getPublicKey());
                    }
                });

        if (isSigningKey) {
            SignatureBuilder primaryBindingSigBuilder = getBuilderForPrimaryKeyBindingSignature(secretKey, subkey)
            builder.addEmbeddedSignature()
        }
    }

    public static SignatureBuilder getBuilderForUserIdCertification() {

    }
}
