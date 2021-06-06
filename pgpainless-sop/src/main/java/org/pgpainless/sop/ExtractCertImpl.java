/*
 * Copyright 2021 Paul Schaub.
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
package org.pgpainless.sop;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.pgpainless.PGPainless;
import org.pgpainless.key.util.KeyRingUtils;
import org.pgpainless.util.ArmorUtils;
import sop.ExtractCert;
import sop.exception.SOPGPException;

public class ExtractCertImpl implements ExtractCert {

    private boolean armor = true;

    @Override
    public ExtractCert noArmor() {
        armor = false;
        return this;
    }

    @Override
    public InputStream key(InputStream keyInputStream) throws IOException, SOPGPException.BadData {
        try {
            PGPSecretKeyRing key = PGPainless.readKeyRing().secretKeyRing(keyInputStream);
            PGPPublicKeyRing cert = KeyRingUtils.publicKeyRingFrom(key);

            if (!armor) {
                return new ByteArrayInputStream(cert.getEncoded());
            } else {
                String armored = ArmorUtils.toAsciiArmoredString(cert);
                return new ByteArrayInputStream(armored.getBytes(StandardCharsets.UTF_8));
            }
        } catch (PGPException e) {
            throw new SOPGPException.BadData(e);
        }
    }
}
