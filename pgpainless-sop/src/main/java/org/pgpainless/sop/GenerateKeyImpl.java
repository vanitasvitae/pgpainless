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
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.Set;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.pgpainless.PGPainless;
import org.pgpainless.key.modification.secretkeyring.SecretKeyRingEditorInterface;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.util.ArmorUtils;
import sop.operation.GenerateKey;
import sop.exception.SOPGPException;

public class GenerateKeyImpl implements GenerateKey {

    private boolean armor = true;
    private final Set<String> userIds = new LinkedHashSet<>();

    @Override
    public GenerateKey noArmor() {
        this.armor = false;
        return this;
    }

    @Override
    public GenerateKey userId(String userId) {
        this.userIds.add(userId);
        return this;
    }

    @Override
    public InputStream generate() throws SOPGPException.MissingArg, SOPGPException.UnsupportedAsymmetricAlgo, IOException {
        Iterator<String> userIdIterator = userIds.iterator();
        if (!userIdIterator.hasNext()) {
            throw new SOPGPException.MissingArg("Missing user-id.");
        }

        PGPSecretKeyRing key;
        try {
             key = PGPainless.generateKeyRing()
                    .modernKeyRing(userIdIterator.next(), null);

            if (userIdIterator.hasNext()) {
                SecretKeyRingEditorInterface editor = PGPainless.modifyKeyRing(key);

                while (userIdIterator.hasNext()) {
                    editor.addUserId(userIdIterator.next(), SecretKeyRingProtector.unprotectedKeys());
                }

                key = editor.done();
            }

            if (armor) {
                String armored = ArmorUtils.toAsciiArmoredString(key);
                return new ByteArrayInputStream(armored.getBytes(StandardCharsets.UTF_8));
            } else {
                return new ByteArrayInputStream(key.getEncoded());
            }

        } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException e) {
            throw new SOPGPException.UnsupportedAsymmetricAlgo(e);
        } catch (PGPException e) {
            throw new RuntimeException(e);
        }
    }
}
