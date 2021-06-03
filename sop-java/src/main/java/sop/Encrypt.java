package sop;

import java.io.InputStream;

import sop.enums.EncryptAs;

public interface Encrypt {

    /**
     * Disable ASCII armor encoding.
     *
     * @return builder instance
     */
    Encrypt noArmor();

    /**
     * Sets encryption mode.
     *
     * @param mode mode
     * @return builder instance
     */
    Encrypt mode(EncryptAs mode);

    /**
     * Adds the signer key.
     *
     * @param key input stream containing the encoded signer key
     * @return builder instance
     */
    Encrypt signWith(InputStream key);

    /**
     * Encrypt with the given password.
     *
     * @param password password
     * @return builder instance
     */
    Encrypt withPassword(String password);

    /**
     * Encrypt with the given cert.
     *
     * @param cert input stream containing the encoded cert.
     * @return builder instance
     */
    Encrypt withCert(InputStream cert);

    /**
     * Encrypt the given data yielding the ciphertext.
     * @param plaintext plaintext
     * @return input stream containing the ciphertext
     */
    InputStream plaintext(InputStream plaintext);
}
