package org.pgpainless.encryption_signing.mark2;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.util.Passphrase;

public interface EncryptionBuilder2 {

    default ToRecipient encrypt(OutputStream outputStream) {
        return encrypt(outputStream, EncryptionOptions.defaultOptions());
    }

    ToRecipient encrypt(OutputStream outputStream, EncryptionOptions encryptionOptions);

    SignWith noEncryption(OutputStream outputStream);

    interface ToRecipient {

        AndToRecipient toRecipient(PGPPublicKeyRing key, String userId);

        AndToRecipient toPassphrase(Passphrase passphrase);

    }

    interface AndToRecipient {

        OptionalRecipient and();

        Done noSigning();
    }

    interface OptionalRecipient extends ToRecipient, SignWith {

    }

    interface SignWith {

        default AndSignWith inlineSignWith(SecretKeyRingProtector protector, PGPSecretKeyRing key, String userId) {
            return inlineSignWith(protector, key, userId, SigningOptions.defaultOptions());
        }

        AndSignWith inlineSignWith(SecretKeyRingProtector protector, PGPSecretKeyRing key, String userId, SigningOptions signingOptions);

        default AndSignWith detachedSignWith(SecretKeyRingProtector protector, PGPSecretKeyRing key, String userId) {
            return detachedSignWith(protector, key, userId, SigningOptions.defaultOptions());
        }

        AndSignWith detachedSignWith(SecretKeyRingProtector protector, PGPSecretKeyRing key, String userId, SigningOptions options);

    }

    interface AndSignWith {
        OptionalSignWith and_();
    }

    interface Done {
        EncryptionStream2 done() throws IOException, PGPException;
    }

    interface OptionalSignWith extends SignWith, AndSignWith, Done {

    }

    public static void test() {
        OutputStream outputStream = new ByteArrayOutputStream();
        EncryptionStream2 stream2 = new EncryptionBuilder2Impl()
                .encrypt(outputStream)
                .toPassphrase(Passphrase.fromPassword("Hello"))
                .and().toPassphrase(Passphrase.emptyPassphrase())
                .and().toRecipient(new PGPPublicKeyRing(), "alice@wonderland.lit")
                .and().inlineSignWith(SecretKeyRingProtector.unprotectedKeys(), new PGPSecretKeyRing(), "alice@wonderland.lit")
                .and_().detachedSignWith(SecretKeyRingProtector.unprotectedKeys(), new PGPSecretKeyRing(), "alice@obsjnasd")
                .and_().done();
    }
}
