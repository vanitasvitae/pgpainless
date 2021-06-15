package org.pgpainless.sop;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Date;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.pgpainless.PGPainless;
import org.pgpainless.decryption_verification.DecryptionBuilderInterface;
import org.pgpainless.decryption_verification.OpenPgpMetadata;
import org.pgpainless.util.Passphrase;
import sop.Decrypt;
import sop.ReadyWithResult;
import sop.SessionKey;
import sop.exception.SOPGPException;

public class DecryptImpl implements Decrypt<OpenPgpMetadata> {

    private Date notBefore;
    private Date notAfter;

    @Override
    public DecryptImpl verifyNotBefore(Date timestamp) throws SOPGPException.UnsupportedOption {
        throw new SOPGPException.UnsupportedOption();
    }

    @Override
    public DecryptImpl verifyNotAfter(Date timestamp) throws SOPGPException.UnsupportedOption {
        throw new SOPGPException.UnsupportedOption();
    }

    @Override
    public DecryptImpl verifyWithCert(InputStream cert) throws SOPGPException.CertCannotSign, SOPGPException.BadData, IOException {
        try {
            PGPPublicKeyRingCollection certs = PGPainless.readKeyRing().keyRingCollection(cert, false)
                    .getPgpPublicKeyRingCollection();

        } catch (PGPException e) {
            throw new SOPGPException.BadData(e);
        }
        return null;
    }

    @Override
    public DecryptImpl withSessionKey(SessionKey sessionKey) throws SOPGPException.UnsupportedOption {
        throw new SOPGPException.UnsupportedOption();
    }

    @Override
    public DecryptImpl withPassword(String password) throws SOPGPException.PasswordNotHumanReadable, SOPGPException.UnsupportedOption {
        return null;
    }

    @Override
    public DecryptImpl withKey(InputStream key) throws SOPGPException.KeyIsProtected, SOPGPException.BadData, SOPGPException.UnsupportedAsymmetricAlgo {
        return null;
    }

    @Override
    public ReadyWithResult<OpenPgpMetadata> ciphertext(InputStream ciphertext) throws SOPGPException.BadData {
        DecryptionBuilderInterface.DecryptWith builder1 = PGPainless.decryptAndOrVerify()
                .onInputStream(ciphertext);

        return new ReadyWithResult<OpenPgpMetadata>() {
            @Override
            public OpenPgpMetadata writeTo(OutputStream outputStream) {

                return null;
            }
        };
    }
}
