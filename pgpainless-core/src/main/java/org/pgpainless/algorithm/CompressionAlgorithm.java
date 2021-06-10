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

import org.bouncycastle.bcpg.CompressionAlgorithmTags;

/**
 * Enumeration of possible compression algorithms.
 *
 * @see <a href="https://tools.ietf.org/html/rfc4880#section-9.3">RFC4880: Compression Algorithm Tags</a>
 */
public enum CompressionAlgorithm {

    UNCOMPRESSED   (CompressionAlgorithmTags.UNCOMPRESSED),
    ZIP            (CompressionAlgorithmTags.ZIP),
    ZLIB           (CompressionAlgorithmTags.ZLIB),
    BZIP2          (CompressionAlgorithmTags.BZIP2),
    ;

    private static final Map<Integer, CompressionAlgorithm> MAP = new ConcurrentHashMap<>();

    static {
        for (CompressionAlgorithm c : CompressionAlgorithm.values()) {
            MAP.put(c.algorithmId, c);
        }
    }

    /**
     * Return the {@link CompressionAlgorithm} value that corresponds to the provided numerical id.
     * If an invalid id is provided, null is returned.
     *
     * @param id id
     * @return compression algorithm
     */
    public static CompressionAlgorithm fromId(int id) {
        return MAP.get(id);
    }

    private final int algorithmId;

    CompressionAlgorithm(int id) {
        this.algorithmId = id;
    }

    /**
     * Return the numerical algorithm tag corresponding to this compression algorithm.
     * @return id
     */
    public int getAlgorithmId() {
        return algorithmId;
    }
}