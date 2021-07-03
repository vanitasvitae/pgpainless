package org.pgpainless.sop;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.util.io.Streams;
import org.pgpainless.PGPainless;
import org.pgpainless.decryption_verification.ConsumerOptions;
import org.pgpainless.decryption_verification.DecryptionStream;
import org.pgpainless.decryption_verification.OpenPgpMetadata;
import org.pgpainless.exception.NotYetImplementedException;
import org.pgpainless.key.OpenPgpV4Fingerprint;
import org.pgpainless.signature.SignatureUtils;
import sop.Result;
import sop.Verification;
import sop.exception.SOPGPException;
import sop.operation.Verify;

public class VerifyImpl implements Verify {

    ConsumerOptions options = new ConsumerOptions();

    @Override
    public Verify notBefore(Date timestamp) throws SOPGPException.UnsupportedOption {
        try {
            options.verifyNotBefore(timestamp);
        } catch (NotYetImplementedException e) {
            throw new SOPGPException.UnsupportedOption();
        }
        return this;
    }

    @Override
    public Verify notAfter(Date timestamp) throws SOPGPException.UnsupportedOption {
        try {
            options.verifyNotAfter(timestamp);
        } catch (NotYetImplementedException e) {
            throw new SOPGPException.UnsupportedOption();
        }
        return this;
    }

    @Override
    public Verify cert(InputStream cert) throws SOPGPException.BadData {
        PGPPublicKeyRingCollection certificates;
        try {
            certificates = PGPainless.readKeyRing().publicKeyRingCollection(cert);
        } catch (IOException | PGPException e) {
            throw new SOPGPException.BadData(e);
        }
        options.addVerificationCerts(certificates);
        return this;
    }

    @Override
    public VerifyImpl signatures(InputStream signatures) throws SOPGPException.BadData {
        List<PGPSignature> signatureList;
        try {
            signatureList = SignatureUtils.readSignatures(signatures);
        } catch (IOException | PGPException e) {
            throw new SOPGPException.BadData(e);
        }
        options.addVerificationOfDetachedSignatures(signatureList);
        return this;
    }

    @Override
    public Result<List<Verification>> data(InputStream data) throws IOException {
        DecryptionStream decryptionStream;
        try {
            decryptionStream = PGPainless.decryptAndOrVerify()
                    .onInputStream(data)
                    .withOptions(options);

            Streams.drain(decryptionStream);
            decryptionStream.close();
            OpenPgpMetadata result = decryptionStream.getResult();
            List<Verification> verifications = new ArrayList<>();
            for (OpenPgpV4Fingerprint fingerprint : result.getVerifiedSignatures().keySet()) {
                PGPSignature signature = result.getVerifiedSignatures().get(fingerprint);
                verifications.add(new Verification(
                        signature.getCreationTime(),
                        // TODO: Use correct fingerprints
                        fingerprint.toString(),
                        fingerprint.toString()));
            }
            return new Result<>(verifications);
        } catch (PGPException e) {
            throw new IOException(e);
        }
    }
}
