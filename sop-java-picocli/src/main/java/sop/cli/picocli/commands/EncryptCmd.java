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
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import picocli.CommandLine;
import sop.Ready;
import sop.cli.picocli.SopCLI;
import sop.enums.EncryptAs;
import sop.exception.SOPGPException;
import sop.operation.Encrypt;

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
    EncryptAs type = EncryptAs.Binary;

    @CommandLine.Option(names = "--with-password",
            description = "Encrypt the message with a password",
            paramLabel = "PASSWORD")
    List<String> withPassword = new ArrayList<>();

    @CommandLine.Option(names = "--sign-with",
            description = "Sign the output with a private key",
            paramLabel = "KEY")
    List<File> signWith = new ArrayList<>();

    @CommandLine.Parameters(description = "Certificates the message gets encrypted to",
            index = "0..*",
            paramLabel = "CERTS")
    List<File> certs = new ArrayList<>();

    @Override
    public void run() {
        Encrypt encrypt = SopCLI.getSop().encrypt();
        try {
            encrypt.mode(type);
        } catch (SOPGPException.UnsupportedOption unsupportedOption) {
            System.err.println("Unsupported option '--as'.");
            unsupportedOption.printStackTrace();
            System.exit(unsupportedOption.getExitCode());
        }

        for (String password : withPassword) {
            try {
                encrypt.withPassword(password);
            } catch (SOPGPException.PasswordNotHumanReadable passwordNotHumanReadable) {
                System.err.println("Password is not human-readable.");
                passwordNotHumanReadable.printStackTrace();
                System.exit(passwordNotHumanReadable.getExitCode());
            } catch (SOPGPException.UnsupportedOption unsupportedOption) {
                System.err.println("Unsupported option '--with-password'.");
                unsupportedOption.printStackTrace();
                System.exit(unsupportedOption.getExitCode());
            }
        }

        for (File keyFile : signWith) {
            try (FileInputStream keyIn = new FileInputStream(keyFile)) {
                encrypt.signWith(keyIn);
            } catch (FileNotFoundException e) {
                System.err.println("Key file " + keyFile.getAbsolutePath() + " not found.");
                e.printStackTrace();
                System.exit(1);
            } catch (IOException e) {
                System.err.println("IO Error.");
                e.printStackTrace();
                System.exit(1);
            } catch (SOPGPException.KeyIsProtected keyIsProtected) {
                System.err.println("Key from " + keyFile.getAbsolutePath() + " is password protected.");
                keyIsProtected.printStackTrace();
                System.exit(1);
            } catch (SOPGPException.UnsupportedAsymmetricAlgo unsupportedAsymmetricAlgo) {
                System.err.println("Key from " + keyFile.getAbsolutePath() + " has unsupported asymmetric algorithm.");
                unsupportedAsymmetricAlgo.printStackTrace();
                System.exit(unsupportedAsymmetricAlgo.getExitCode());
            } catch (SOPGPException.CertCannotSign certCannotSign) {
                System.err.println("Key from " + keyFile.getAbsolutePath() + " cannot sign.");
                certCannotSign.printStackTrace();
                System.exit(1);
            } catch (SOPGPException.BadData badData) {
                System.err.println("Key file " + keyFile.getAbsolutePath() + " does not contain a valid OpenPGP private key.");
                badData.printStackTrace();
                System.exit(badData.getExitCode());
            }
        }

        for (File certFile : certs) {
            try (FileInputStream certIn = new FileInputStream(certFile)) {
                encrypt.withCert(certIn);
            } catch (FileNotFoundException e) {
                System.err.println("Certificate file " + certFile.getAbsolutePath() + " not found.");
                e.printStackTrace();
                System.exit(1);
            } catch (IOException e) {
                System.err.println("IO Error.");
                e.printStackTrace();
                System.exit(1);
            } catch (SOPGPException.UnsupportedAsymmetricAlgo unsupportedAsymmetricAlgo) {
                System.err.println("Certificate from " + certFile.getAbsolutePath() + " has unsupported asymmetric algorithm.");
                unsupportedAsymmetricAlgo.printStackTrace();
                System.exit(unsupportedAsymmetricAlgo.getExitCode());
            } catch (SOPGPException.CertCannotEncrypt certCannotEncrypt) {
                System.err.println("Certificate from " + certFile.getAbsolutePath() + " is not capable of encryption.");
                certCannotEncrypt.printStackTrace();
                System.exit(certCannotEncrypt.getExitCode());
            } catch (SOPGPException.BadData badData) {
                System.err.println("Certificate file " + certFile.getAbsolutePath() + " does not contain a valid OpenPGP certificate.");
                badData.printStackTrace();
                System.exit(badData.getExitCode());
            }
        }

        if (!armor) {
            encrypt.noArmor();
        }

        try {
            Ready ready = encrypt.plaintext(System.in);
            ready.writeTo(System.out);
        } catch (IOException e) {
            System.err.println("IO Error.");
            e.printStackTrace();
            System.exit(1);
        }
    }
}
