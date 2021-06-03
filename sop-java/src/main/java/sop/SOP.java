package sop;

public interface SOP {

    /**
     * Get information about the implementations name and version.
     *
     * @return version
     */
    Version version();

    GenerateKey generateKey();
}
