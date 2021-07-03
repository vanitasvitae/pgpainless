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

import picocli.CommandLine;
import sop.cli.picocli.SopCLI;
import sop.enums.SignAs;
import sop.exception.SOPGPException;
import sop.operation.Sign;

@CommandLine.Command(name = "sign",
        description = "Create a detached signature on the data from standard input",
        exitCodeOnInvalidInput = 37)
public class SignCmd implements Runnable {

    @CommandLine.Option(names = "--no-armor",
            description = "ASCII armor the output",
            negatable = true)
    boolean armor = true;

    @CommandLine.Option(names = "--as", description = "Defaults to 'binary'. If '--as=text' and the input data is not valid UTF-8, sign fails with return code 53.",
            paramLabel = "{binary|text}")
    SignAs type;

    @CommandLine.Parameters(description = "Secret keys used for signing",
            paramLabel = "KEY",
            arity = "1..*")
    File[] secretKeyFile;

    @Override
    public void run() {
        Sign sign = SopCLI.getSop().sign();
        sign.mode(type);

        for (File keyFile : secretKeyFile) {
            try (FileInputStream keyIn = new FileInputStream(keyFile)) {
                sign.key(keyIn);
            } catch (FileNotFoundException e) {
                System.err.println("File " + keyFile.getAbsolutePath() + " does not exist.");
                e.printStackTrace();
            } catch (IOException e) {
                System.err.println("Cannot access file " + keyFile.getAbsolutePath());
                e.printStackTrace();
            } catch (SOPGPException.KeyIsProtected e) {
                System.err.println("Key " + keyFile.getName() + " is password protected.");
                e.printStackTrace();
            } catch (SOPGPException.BadData badData) {
                System.err.println("Bad data in key file " + keyFile.getAbsolutePath() + ":");
                badData.printStackTrace();
            }
        }

        if (!armor) {
            sign.noArmor();
        }
    }
}
