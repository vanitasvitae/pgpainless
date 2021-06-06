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
package org.pgpainless.cli;

import org.pgpainless.cli.commands.Armor;
import org.pgpainless.cli.commands.Dearmor;
import org.pgpainless.cli.commands.Decrypt;
import org.pgpainless.cli.commands.Encrypt;
import org.pgpainless.cli.commands.ExtractCert;
import org.pgpainless.cli.commands.GenerateKey;
import org.pgpainless.cli.commands.Sign;
import org.pgpainless.cli.commands.Verify;
import org.pgpainless.cli.commands.Version;
import picocli.CommandLine;

@CommandLine.Command(exitCodeOnInvalidInput = 69,
        subcommands = {
                Armor.class,
                Dearmor.class,
                Decrypt.class,
                Encrypt.class,
                ExtractCert.class,
                GenerateKey.class,
                Sign.class,
                Verify.class,
                Version.class
        }
)
public class PGPainlessCLI implements Runnable {

    public PGPainlessCLI() {

    }

    public static void main(String[] args) {
        int code = new CommandLine(new PGPainlessCLI())
                .execute(args);
        System.exit(code);
    }

    @Override
    public void run() {

    }
}
