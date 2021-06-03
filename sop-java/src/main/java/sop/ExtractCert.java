package sop;

import java.io.InputStream;

public interface ExtractCert {

    /**
     * Disable ASCII armor encoding.
     *
     * @return builder instance
     */
    ExtractCert noArmor();

    /**
     * Extract the cert from the provided key.
     *
     * @param keyInputStream input stream containing the encoding of an OpenPGP key
     * @return input stream containing the encoding of the keys cert
     */
    InputStream key(InputStream keyInputStream);
}
