/*
 * Copyright 2018 Paul Schaub.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.vanitasvitae.crypto.pgpainless.decryption_verification;

import java.io.IOException;
import java.io.InputStream;
import java.util.Set;

import de.vanitasvitae.crypto.pgpainless.key.SecretKeyRingProtector;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;

public interface DecryptionBuilderInterface {

    DecryptWith onInputStream(InputStream inputStream);

    interface DecryptWith {

        VerifyWith decryptWith(PGPSecretKeyRingCollection secretKeyRings, SecretKeyRingProtector decryptor);

        VerifyWith doNotDecrypt();

    }

    interface VerifyWith {

        MissingPublicKeyFeedback verifyWith(Set<Long> trustedFingerprints, PGPPublicKeyRingCollection publicKeyRings);

        MissingPublicKeyFeedback verifyWith(Set<Long> trustedFingerprints, Set<PGPPublicKeyRing> publicKeyRings);

        Build doNotVerify();

    }

    interface MissingPublicKeyFeedback {

        Build handleMissingPublicKeysWith(MissingPublicKeyCallback callback);

        Build ignoreMissingPublicKeys();
    }

    interface Build {

        DecryptionStream build() throws IOException, PGPException;

    }

}
