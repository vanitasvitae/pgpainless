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
import sop.Result;
import sop.Verification;
import sop.cli.picocli.DateParser;
import sop.cli.picocli.SopCLI;
import sop.exception.SOPGPException;
import sop.operation.Verify;

@CommandLine.Command(name = "verify",
        description = "Verify a detached signature over the data from standard input",
        exitCodeOnInvalidInput = 37)
public class VerifyCmd implements Runnable {

    @CommandLine.Parameters(index = "0",
            description = "Detached signature",
            paramLabel = "SIGNATURE")
    File signature;

    @CommandLine.Parameters(index = "1..*",
            arity = "1..*",
            description = "Public key certificates",
            paramLabel = "CERT")
    List<File> certificates = new ArrayList<>();

    @CommandLine.Option(names = {"--not-before"},
            description = "ISO-8601 formatted UTC date (eg. '2020-11-23T16:35Z)\n" +
                    "Reject signatures with a creation date not in range.\n" +
                    "Defaults to beginning of time (\"-\").",
            paramLabel = "DATE")
    String notBefore = "-";

    @CommandLine.Option(names = {"--not-after"},
            description = "ISO-8601 formatted UTC date (eg. '2020-11-23T16:35Z)\n" +
                    "Reject signatures with a creation date not in range.\n" +
                    "Defaults to current system time (\"now\").\n" +
                    "Accepts special value \"-\" for end of time.",
            paramLabel = "DATE")
    String notAfter = "now";

    @Override
    public void run() {
        Verify verify = SopCLI.getSop().verify();
        if (notAfter != null) {
            try {
                verify.notAfter(DateParser.parseNotAfter(notAfter));
            } catch (SOPGPException.UnsupportedOption unsupportedOption) {
                System.err.println("Unsupported option '--not-after'.");
                unsupportedOption.printStackTrace();
                // System.exit(unsupportedOption.getExitCode());
            }
        }
        if (notBefore != null) {
            try {
                verify.notBefore(DateParser.parseNotBefore(notBefore));
            } catch (SOPGPException.UnsupportedOption unsupportedOption) {
                System.err.println("Unsupported option '--not-before'.");
                unsupportedOption.printStackTrace();
                // System.exit(unsupportedOption.getExitCode());
            }
        }

        for (File certFile : certificates) {
            try (FileInputStream certIn = new FileInputStream(certFile)) {
                verify.cert(certIn);
            } catch (FileNotFoundException fileNotFoundException) {
                System.err.println("Certificate file " + certFile.getAbsolutePath() + " not found.");
                fileNotFoundException.printStackTrace();
                System.exit(1);
            } catch (IOException ioException) {
                System.err.println("IO Error.");
                ioException.printStackTrace();
                System.exit(1);
            } catch (SOPGPException.BadData badData) {
                System.err.println("Certificate file " + certFile.getAbsolutePath() + " appears to not contain a valid OpenPGP certificate.");
                badData.printStackTrace();
                System.exit(badData.getExitCode());
            }
        }

        if (signature != null) {
            try (FileInputStream sigIn = new FileInputStream(signature)) {
                verify.signatures(sigIn);
            } catch (FileNotFoundException e) {
                System.err.println("Signature");
                e.printStackTrace();
            } catch (IOException e) {
                e.printStackTrace();
            } catch (SOPGPException.BadData badData) {
                System.err.println("File " + signature.getAbsolutePath() + " does not contain a valid OpenPGP signature.");
                badData.printStackTrace();
                System.exit(badData.getExitCode());
            }
        }

        Result<List<Verification>> verifications = null;
        try {
            verifications = verify.data(System.in);
        } catch (IOException ioException) {
            System.err.println("IO Error.");
            ioException.printStackTrace();
            System.exit(1);
        }
        for (Verification verification : verifications.get()) {
            System.out.println(verification.toString());
        }
    }
}
