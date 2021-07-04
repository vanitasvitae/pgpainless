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
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import picocli.CommandLine;
import sop.DecryptionResult;
import sop.ReadyWithResult;
import sop.SessionKey;
import sop.cli.picocli.DateParser;
import sop.cli.picocli.SopCLI;
import sop.exception.SOPGPException;
import sop.operation.Decrypt;

@CommandLine.Command(name = "decrypt",
        description = "Decrypt a message from standard input",
        exitCodeOnInvalidInput = SOPGPException.UnsupportedOption.EXIT_CODE)
public class DecryptCmd implements Runnable {

    private static final DateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm'Z'");

    @CommandLine.Option(
            names = {"--session-key-out"},
            description = "Can be used to learn the session key on successful decryption",
            paramLabel = "SESSIONKEY")
    File sessionKeyOut;

    @CommandLine.Option(
            names = {"--with-session-key"},
            description = "Enables decryption of the \"CIPHERTEXT\" using the session key directly against the \"SEIPD\" packet",
            paramLabel = "SESSIONKEY")
    List<String> withSessionKey = new ArrayList<>();

    @CommandLine.Option(
            names = {"--with-password"},
            description = "Enables decryption based on any \"SKESK\" packets in the \"CIPHERTEXT\"",
            paramLabel = "PASSWORD")
    List<String> withPassword = new ArrayList<>();

    @CommandLine.Option(names = {"--verify-out"},
            description = "Produces signature verification status to the designated file",
            paramLabel = "VERIFICATIONS")
    File verifyOut;

    @CommandLine.Option(names = {"--verify-with"},
            description = "Certificates whose signatures would be acceptable for signatures over this message",
            paramLabel = "CERT")
    List<File> certs = new ArrayList<>();

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

    @CommandLine.Parameters(index = "0..*",
            description = "Secret keys to attempt decryption with",
            paramLabel = "KEY")
    List<File> keys = new ArrayList<>();

    @Override
    public void run() {
        unlinkExistingVerifyOut(verifyOut);

        Decrypt decrypt = SopCLI.getSop().decrypt();
        setNotAfter(notAfter, decrypt);
        setNotBefore(notBefore, decrypt);
        setWithPasswords(withPassword, decrypt);
        setWithSessionKeys(withSessionKey, decrypt);
        setSessionKeyOut(sessionKeyOut, decrypt);
        setVerifyWith(certs, decrypt);
        setDecryptWith(keys, decrypt);

        try {
            ReadyWithResult<DecryptionResult> ready = decrypt.ciphertext(System.in);
            DecryptionResult result = ready.writeTo(System.out);
            if (sessionKeyOut != null) {
                if (sessionKeyOut.exists()) {
                    System.err.println("File " + sessionKeyOut.getAbsolutePath() + " already exists.");
                    new SOPGPException.OutputExists().printStackTrace();
                    System.exit(1);
                }

                try (FileOutputStream outputStream = new FileOutputStream(sessionKeyOut)) {
                    if (!result.getSessionKey().isPresent()) {
                        System.err.println("Session key not extracted. Possibly the feature is not supported.");
                        System.exit(SOPGPException.UnsupportedOption.EXIT_CODE);
                    } else {
                        SessionKey sessionKey = result.getSessionKey().get();
                        outputStream.write(sessionKey.getAlgorithm());
                        outputStream.write(sessionKey.getKey());
                    }
                }
            }
        } catch (SOPGPException.BadData badData) {
            System.err.println("No valid OpenPGP message found on Standard Input.");
            badData.printStackTrace();
            System.exit(badData.getExitCode());
        } catch (SOPGPException.MissingArg missingArg) {
            System.err.println("Missing arguments.");
            missingArg.printStackTrace();
            System.exit(missingArg.getExitCode());
        } catch (IOException e) {
            System.err.println("IO Error.");
            e.printStackTrace();
            System.exit(1);
        } catch (SOPGPException.NoSignature noSignature) {
            System.err.println("No verifiable signature found.");
            noSignature.printStackTrace();
            System.exit(noSignature.getExitCode());
        }
    }

    private void setDecryptWith(List<File> keys, Decrypt decrypt) {
        for (File key : keys) {
            try (FileInputStream keyIn = new FileInputStream(key)) {
                decrypt.withKey(keyIn);
            } catch (SOPGPException.KeyIsProtected keyIsProtected) {
                System.err.println("Key in file " + key.getAbsolutePath() + " is password protected.");
                keyIsProtected.printStackTrace();
                System.exit(1);
            } catch (SOPGPException.UnsupportedAsymmetricAlgo unsupportedAsymmetricAlgo) {
                System.err.println("Key uses unsupported asymmetric algorithm.");
                unsupportedAsymmetricAlgo.printStackTrace();
                System.exit(unsupportedAsymmetricAlgo.getExitCode());
            } catch (SOPGPException.BadData badData) {
                System.err.println("File " + key.getAbsolutePath() + " does not contain a private key.");
                badData.printStackTrace();
                System.exit(badData.getExitCode());
            } catch (FileNotFoundException e) {
                System.err.println("File " + key.getAbsolutePath() + " does not exist.");
                e.printStackTrace();
                System.exit(1);
            } catch (IOException e) {
                System.err.println("IO Error.");
                e.printStackTrace();
                System.exit(1);
            }
        }
    }

    private void setVerifyWith(List<File> certs, Decrypt decrypt) {
        for (File cert : certs) {
            try (FileInputStream certIn = new FileInputStream(cert)) {
                decrypt.verifyWithCert(certIn);
            } catch (FileNotFoundException e) {
                System.err.println("File " + cert.getAbsolutePath() + " does not exist.");
                e.printStackTrace();
                System.exit(1);
            } catch (IOException e) {
                System.err.println("IO Error.");
                e.printStackTrace();
                System.exit(1);
            } catch (SOPGPException.BadData badData) {
                System.err.println("File " + cert.getAbsolutePath() + " does not contain a valid certificate.");
                badData.printStackTrace();
                System.exit(badData.getExitCode());
            }
        }
    }

    private void unlinkExistingVerifyOut(File verifyOut) {
        if (verifyOut == null) {
            return;
        }

        if (verifyOut.exists()) {
            if (!verifyOut.delete()) {
                System.err.println("Cannot delete existing verification file" + verifyOut.getAbsolutePath());
                System.exit(1);
            }
        }
    }

    private void setSessionKeyOut(File sessionKeyOut, Decrypt decrypt) {
        if (sessionKeyOut == null) {
            return;
        }

        System.err.println("Unsupported option '--session-key-out'.");
        System.exit(SOPGPException.UnsupportedOption.EXIT_CODE);
    }

    private void setWithSessionKeys(List<String> withSessionKey, Decrypt decrypt) {
        for (String sessionKey : withSessionKey) {
            byte[] bytes = sessionKey.getBytes(StandardCharsets.UTF_8);
            byte algorithm = bytes[0];
            byte[] key = new byte[bytes.length - 1];
            System.arraycopy(bytes, 1, key, 0, key.length);

            try {
                decrypt.withSessionKey(new SessionKey(algorithm, key));
            } catch (SOPGPException.UnsupportedOption unsupportedOption) {
                System.err.println("Unsupported option '--with-session-key'.");
                unsupportedOption.printStackTrace();
                System.exit(unsupportedOption.getExitCode());
                return;
            }
        }
    }

    private void setWithPasswords(List<String> withPassword, Decrypt decrypt) {
        for (String password : withPassword) {
            try {
                decrypt.withPassword(password);
            } catch (SOPGPException.PasswordNotHumanReadable passwordNotHumanReadable) {
                System.err.println("Password not human readable.");
                passwordNotHumanReadable.printStackTrace();
                System.exit(passwordNotHumanReadable.getExitCode());
            } catch (SOPGPException.UnsupportedOption unsupportedOption) {
                System.err.println("Unsupported option '--with-password'.");
                unsupportedOption.printStackTrace();
                System.exit(unsupportedOption.getExitCode());
            }
        }
    }

    private void setNotAfter(String notAfter, Decrypt decrypt) {
        if (notAfter == null) {
            return;
        }

        Date notAfterDate = DateParser.parseNotAfter(notAfter);
        try {
            decrypt.verifyNotAfter(notAfterDate);
        } catch (SOPGPException.UnsupportedOption unsupportedOption) {
            System.err.println("Option '--not-after' not supported.");
            unsupportedOption.printStackTrace();
            // System.exit(unsupportedOption.getExitCode());
        }
    }

    private void setNotBefore(String notBefore, Decrypt decrypt) {
        if (notBefore == null) {
            return;
        }

        Date notBeforeDate = DateParser.parseNotBefore(notBefore);
        try {
            decrypt.verifyNotBefore(notBeforeDate);
        } catch (SOPGPException.UnsupportedOption unsupportedOption) {
            System.err.println("Option '--not-before' not supported.");
            unsupportedOption.printStackTrace();
            // System.exit(unsupportedOption.getExitCode());
        }
    }
}
