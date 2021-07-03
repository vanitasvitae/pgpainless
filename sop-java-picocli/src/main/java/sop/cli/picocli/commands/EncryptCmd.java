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
package sop.cli.picocli.commands;

import java.io.File;

import picocli.CommandLine;
import sop.enums.EncryptAs;

@CommandLine.Command(name = "encrypt",
        description = "Encrypt a message from standard input",
        exitCodeOnInvalidInput = 37)
public class EncryptCmd implements Runnable {

    @CommandLine.Option(names = "--no-armor",
            description = "ASCII armor the output",
            negatable = true)
    boolean armor = true;

    @CommandLine.Option(names = {"--as"},
            description = "Type of the input data. Defaults to 'binary'",
            paramLabel = "{binary|text|mime}")
    EncryptAs type;

    @CommandLine.Option(names = "--with-password",
            description = "Encrypt the message with a password",
            paramLabel = "PASSWORD")
    String[] withPassword = new String[0];

    @CommandLine.Option(names = "--sign-with",
            description = "Sign the output with a private key",
            paramLabel = "KEY")
    File[] signWith = new File[0];

    @CommandLine.Parameters(description = "Certificates the message gets encrypted to",
            index = "0..*",
            paramLabel = "CERTS")
    File[] certs = new File[0];

    @Override
    public void run() {

    }
}
