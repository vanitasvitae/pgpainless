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
package org.pgpainless.algorithm;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.bouncycastle.bcpg.sig.Features;

/**
 * An enumeration of features that may be set in the {@link Features} subpacket.
 *
 * @see <a href="https://tools.ietf.org/html/rfc4880#section-5.2.3.24">RFC4880: Features</a>
 */
public enum Feature {

    /**
     * Add modification detection package.
     *
     * @see <a href="https://tools.ietf.org/html/rfc4880#section-5.14">
     *     RFC-4880 §5.14: Modification Detection Code Packet</a>
     */
    MODIFICATION_DETECTION(Features.FEATURE_MODIFICATION_DETECTION),
    ;

    private static final Map<Byte, Feature> MAP = new ConcurrentHashMap<>();

    static {
        for (Feature f : Feature.values()) {
            MAP.put(f.featureId, f);
        }
    }

    public static Feature fromId(byte id) {
        return MAP.get(id);
    }

    private final byte featureId;

    Feature(byte featureId) {
        this.featureId = featureId;
    }

    public byte getFeatureId() {
        return featureId;
    }
}
