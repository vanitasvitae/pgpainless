package sop;

import java.io.InputStream;
import java.util.Date;

public interface Verify {

    /**
     * Makes the SOP implementation consider signatures before this date invalid.
     *
     * @param timestamp timestamp
     * @return builder instance
     */
    Verify notBefore(Date timestamp);

    /**
     * Makes the SOP implementation consider signatures after this date invalid.
     *
     * @param timestamp timestamp
     * @return builder instance
     */
    Verify notAfter(Date timestamp);

    /**
     * Adds the verification cert.
     *
     * @param cert input stream containing the encoded cert
     * @return builder instance
     */
    Verify cert(InputStream cert);

    /**
     * Provides the signatures.
     * @param signatures input stream containing encoded, detached signatures.
     *
     * @return builder instance
     */
    VerifySignatures signatures(InputStream signatures);

}
