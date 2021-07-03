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

import java.io.IOException;

import picocli.CommandLine;
import sop.Ready;
import sop.cli.picocli.SopCLI;
import sop.enums.ArmorLabel;
import sop.exception.SOPGPException;
import sop.operation.Armor;

@CommandLine.Command(name = "armor",
        description = "Add ASCII Armor to standard input",
        exitCodeOnInvalidInput = SOPGPException.UnsupportedOption.EXIT_CODE)
public class ArmorCmd implements Runnable {

    @CommandLine.Option(names = {"--label"}, description = "Label to be used in the header and tail of the armoring.", paramLabel = "{auto|sig|key|cert|message}")
    ArmorLabel label;

    @CommandLine.Option(names = {"--allow-nested"}, description = "Allow additional armoring of already armored input")
    boolean allowNested = false;

    @Override
    public void run() {
        Armor armor = SopCLI.getSop().armor();
        if (label != null) {
            try {
                armor.label(label);
            } catch (SOPGPException.UnsupportedOption unsupportedOption) {
                System.err.println("Armor labels not supported.");
                System.exit(unsupportedOption.getExitCode());
                return;
            }
        }

        try {
            Ready ready = armor.data(System.in);
            ready.writeTo(System.out);
        } catch (SOPGPException.BadData badData) {
            System.err.println("Bad data.");
            badData.printStackTrace();
            System.exit(badData.getExitCode());
        } catch (IOException e) {
            System.err.println("IO Error.");
            e.printStackTrace();
            System.exit(1);
        }
    }
}
