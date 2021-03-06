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
package org.pgpainless.exception;

import org.bouncycastle.openpgp.PGPException;

/**
 * Exception that gets thrown if unacceptable algorithms are encountered.
 */
public class UnacceptableAlgorithmException extends PGPException {

    public UnacceptableAlgorithmException(String message) {
        super(message);
    }
}
