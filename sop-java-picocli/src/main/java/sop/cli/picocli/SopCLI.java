package sop.cli.picocli;

import picocli.CommandLine;
import sop.SOP;
import sop.cli.picocli.commands.ArmorCmd;
import sop.cli.picocli.commands.DearmorCmd;
import sop.cli.picocli.commands.DecryptCmd;
import sop.cli.picocli.commands.EncryptCmd;
import sop.cli.picocli.commands.ExtractCertCmd;
import sop.cli.picocli.commands.GenerateKeyCmd;
import sop.cli.picocli.commands.SignCmd;
import sop.cli.picocli.commands.VerifyCmd;
import sop.cli.picocli.commands.VersionCmd;

@CommandLine.Command(exitCodeOnInvalidInput = 69,
        subcommands = {
                ArmorCmd.class,
                DearmorCmd.class,
                DecryptCmd.class,
                EncryptCmd.class,
                ExtractCertCmd.class,
                GenerateKeyCmd.class,
                SignCmd.class,
                VerifyCmd.class,
                VersionCmd.class
        }
)
public class SopCLI {

    public static SOP SOP_INSTANCE;

    public static int execute(String[] args) {
        return new CommandLine(SopCLI.class).execute(args);
    }

    public static SOP getSop() {
        if (SOP_INSTANCE == null) {
            throw new IllegalStateException("No SOP backend set.");
        }
        return SOP_INSTANCE;
    }

    public static void setSopInstance(SOP instance) {
        SOP_INSTANCE = instance;
    }
}
