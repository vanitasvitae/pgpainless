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
package sop;

import java.io.InputStream;
import java.util.Date;

public interface Verify {

    /**
     * Makes the SOP implementation consider signatures before this date invalid.
     *
     * @param timestamp timestamp
     * @return builder instance
     */
    Verify notBefore(Date timestamp);

    /**
     * Makes the SOP implementation consider signatures after this date invalid.
     *
     * @param timestamp timestamp
     * @return builder instance
     */
    Verify notAfter(Date timestamp);

    /**
     * Adds the verification cert.
     *
     * @param cert input stream containing the encoded cert
     * @return builder instance
     */
    Verify cert(InputStream cert);

    /**
     * Provides the signatures.
     * @param signatures input stream containing encoded, detached signatures.
     *
     * @return builder instance
     */
    VerifySignatures signatures(InputStream signatures);

}
