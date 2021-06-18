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
package org.pgpainless.algorithm.negotiation;

import java.util.List;

import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.policy.Policy;

public interface HashAlgorithmNegotiator {

    HashAlgorithm negotiateHashAlgorithm(List<HashAlgorithm> preferredHashAlgorithms);

    /**
     * Factory method for an implementation of the {@link HashAlgorithmNegotiator} which returns
     * the first {@link HashAlgorithm} in the provided list which is acceptable by the signature hash algorithm
     * policy set in {@link Policy#setSignatureHashAlgorithmPolicy(Policy.HashAlgorithmPolicy)}.
     *
     * If no acceptable algorithm is encountered in the list, the value of
     * {@link Policy.HashAlgorithmPolicy#defaultHashAlgorithm()} will be returned.
     *
     * @return hash algorithm negotiator
     */
    static HashAlgorithmNegotiator defaultNegotiator() {
        return new HashAlgorithmNegotiator() {
            @Override
            public HashAlgorithm negotiateHashAlgorithm(List<HashAlgorithm> preferredHashAlgorithms) {
                Policy policy = PGPainless.getPolicy();
                for (HashAlgorithm option : preferredHashAlgorithms) {
                    if (policy.getSignatureHashAlgorithmPolicy().isAcceptable(option)) {
                        return option;
                    }
                }

                return PGPainless.getPolicy().getSignatureHashAlgorithmPolicy().defaultHashAlgorithm();
            }
        };
    }
}
