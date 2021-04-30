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
package org.pgpainless.signature;

import java.util.Comparator;

import org.bouncycastle.openpgp.PGPSignature;

public class SignatureValidityComparator implements Comparator<PGPSignature> {

    private final SignatureCreationDateComparator.Order order;
    private final SignatureCreationDateComparator creationDateComparator;

    public SignatureValidityComparator() {
        this(SignatureCreationDateComparator.DEFAULT_ORDER);
    }

    public SignatureValidityComparator(SignatureCreationDateComparator.Order order) {
        this.order = order;
        this.creationDateComparator = new SignatureCreationDateComparator(order);
    }

    @Override
    public int compare(PGPSignature one, PGPSignature two) {
        boolean oneIsHard = SignatureUtils.isHardRevocation(one);
        boolean twoIsHard = SignatureUtils.isHardRevocation(two);

        // both have same "hardness", so compare creation time
        if (oneIsHard == twoIsHard) {
            return creationDateComparator.compare(one, two);
        }
        // favor the "harder" signature
        return oneIsHard ? -1 : 1;
    }
}
