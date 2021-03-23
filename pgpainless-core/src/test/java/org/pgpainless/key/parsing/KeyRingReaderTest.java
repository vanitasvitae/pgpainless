/*
 * Copyright 2021 Paul Schaub
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
package org.pgpainless.key.parsing;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collection;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPUtil;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.key.util.KeyRingUtils;

class KeyRingReaderTest {

    @Test
    public void assertThatPGPUtilsDetectAsciiArmoredData() throws IOException, PGPException {
        InputStream inputStream = getClass().getClassLoader().getResourceAsStream("pub_keys_10_pieces.asc");

        InputStream possiblyArmored = PGPUtil.getDecoderStream(PGPUtil.getDecoderStream(inputStream));

        PGPPublicKeyRingCollection collection = new PGPPublicKeyRingCollection(
                possiblyArmored, ImplementationFactory.getInstance().getKeyFingerprintCalculator());
        assertEquals(10, collection.size());
    }

    @Test
    void publicKeyRingCollectionFromStream() throws IOException, PGPException {
        InputStream inputStream = getClass().getClassLoader().getResourceAsStream("pub_keys_10_pieces.asc");
        PGPPublicKeyRingCollection rings = PGPainless.readKeyRing().publicKeyRingCollection(inputStream);
        assertEquals(10, rings.size());
    }

    @Test
    void publicKeyRingCollectionFromNotArmoredStream() throws IOException, PGPException,
            InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        Collection<PGPPublicKeyRing> collection = new ArrayList<>();

        for (int i = 0; i < 10; i++) {
            PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing().simpleEcKeyRing("user_" + i + "@encrypted.key");
            collection.add(KeyRingUtils.publicKeyRingFrom(secretKeys));
        }

        PGPPublicKeyRingCollection originalRings = new PGPPublicKeyRingCollection(collection);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        originalRings.encode(out);

        ByteArrayInputStream inputStream = new ByteArrayInputStream(out.toByteArray());
        PGPPublicKeyRingCollection parsedRings = PGPainless.readKeyRing().publicKeyRingCollection(inputStream);
        assertEquals(10, parsedRings.size());
    }

    @Test
    void publicKeyRingCollectionFromString() throws IOException, PGPException, URISyntaxException {
        URL resource = getClass().getClassLoader().getResource("pub_keys_10_pieces.asc");
        String armoredString = new String(Files.readAllBytes(new File(resource.toURI()).toPath()));
        InputStream inputStream = new ByteArrayInputStream(armoredString.getBytes(StandardCharsets.UTF_8));
        PGPPublicKeyRingCollection rings = PGPainless.readKeyRing().publicKeyRingCollection(inputStream);
        assertEquals(10, rings.size());
    }

    @Test
    void publicKeyRingCollectionFromBytes() throws IOException, PGPException, URISyntaxException {
        URL resource = getClass().getClassLoader().getResource("pub_keys_10_pieces.asc");
        byte[] bytes = Files.readAllBytes(new File(resource.toURI()).toPath());
        InputStream byteArrayInputStream = new ByteArrayInputStream(bytes);
        PGPPublicKeyRingCollection rings = PGPainless.readKeyRing().publicKeyRingCollection(byteArrayInputStream);
        assertEquals(10, rings.size());
    }

}