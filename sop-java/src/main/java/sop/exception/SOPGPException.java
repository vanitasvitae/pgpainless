package sop.exception;

public class SOPGPException extends Exception {

    public static class NoSignature extends SOPGPException {

    }

    public static class UnsupportedAsymmetricAlgo extends SOPGPException {

    }

    public static class CertCannotEncrypt extends SOPGPException {

    }

    public static class CertCannotSign extends SOPGPException {

    }

    public static class MissingArg extends SOPGPException {

    }

    public static class IncompleteVerification extends SOPGPException {

    }

    public static class CannotDecrypt extends SOPGPException {

    }

    public static class PasswordNotHumanReadable extends SOPGPException {

    }

    public static class UnsupportedOption extends SOPGPException {

    }

    public static class BadData extends SOPGPException {

    }

    public static class ExpectedText extends SOPGPException {

    }

    public static class OutputExists extends SOPGPException {

    }

    public static class KeyIsProtected extends SOPGPException {

    }

    public static class AmbiguousInput extends SOPGPException {

    }

    public static class NotImplemented extends SOPGPException {

    }
}
