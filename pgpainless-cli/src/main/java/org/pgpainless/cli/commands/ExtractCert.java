/*
 * Copyright 2020 Paul Schaub.
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
package org.pgpainless.cli.commands;

import static org.pgpainless.cli.Print.err_ln;
import static org.pgpainless.cli.Print.print_ln;

import java.io.IOException;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.pgpainless.PGPainless;
import org.pgpainless.key.util.KeyRingUtils;
import org.pgpainless.cli.Print;
import picocli.CommandLine;

@CommandLine.Command(name = "extract-cert",
        description = "Extract a public key certificate from a secret key from standard input",
        exitCodeOnInvalidInput = 37)
public class ExtractCert implements Runnable {

    @CommandLine.Option(names = "--no-armor",
            description = "ASCII armor the output",
            negatable = true)
    boolean armor = true;

    @Override
    public void run() {
        try {
            PGPSecretKeyRing secretKeys = PGPainless.readKeyRing().secretKeyRing(System.in);
            PGPPublicKeyRing publicKeys = KeyRingUtils.publicKeyRingFrom(secretKeys);

            print_ln(Print.toString(publicKeys, armor));
        } catch (IOException | PGPException e) {
            err_ln("Error extracting certificate from keys;");
            err_ln(e.getMessage());
            System.exit(1);
        }
    }
}
