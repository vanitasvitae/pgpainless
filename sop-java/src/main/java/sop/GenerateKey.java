package sop;

import java.io.InputStream;

public interface GenerateKey {

    /**
     * Disable ASCII armor encoding.
     *
     * @return builder instance
     */
    GenerateKey noArmor();

    /**
     * Adds a user-id.
     *
     * @param userId user-id
     * @return builder instance
     */
    GenerateKey userId(String userId);

    /**
     * Generate the OpenPGP key and return it encoded as an {@link InputStream}.
     *
     * @return key
     */
    InputStream generate();
}
