package sop;

import java.io.InputStream;
import java.util.Date;

public interface Decrypt {

    /**
     * Makes the SOP consider signatures before this date invalid.
     *
     * @param timestamp timestamp
     * @return builder instance
     */
    Decrypt verifyNotBefore(Date timestamp);

    /**
     * Makes the SOP consider signatures after this date invalid.
     *
     * @param timestamp timestamp
     * @return builder instance
     */
    Decrypt verifyNotAfter(Date timestamp);

    /**
     * Adds the verification cert.
     *
     * @param cert input stream containing the cert
     * @return builder instance
     */
    Decrypt verifyWithCert(InputStream cert);

    /**
     * Tries to decrypt with the given session key.
     *
     * @param sessionKey session key
     * @return builder instance
     */
    Decrypt withSessionKey(SessionKey sessionKey);

    /**
     * Tries to decrypt with the given password.
     *
     * @param password password
     * @return builder instance
     */
    Decrypt withPassword(String password);

    /**
     * Adds the decryption key.
     *
     * @param key input stream containing the key
     * @return builder instance
     */
    Decrypt withKey(InputStream key);

    /**
     * Decrypts the given ciphertext, returning verification results and plaintext.
     * @param ciphertext
     * @return
     */
    InputStream ciphertext(InputStream ciphertext);
}
