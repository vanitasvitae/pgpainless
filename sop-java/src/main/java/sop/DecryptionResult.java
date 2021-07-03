package sop;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

public class DecryptionResult {

    private final Optional<SessionKey> sessionKey;
    private final List<Verification> verifications;

    public DecryptionResult(SessionKey sessionKey, List<Verification> verifications) {
        this.sessionKey = Optional.ofNullable(sessionKey);
        this.verifications = Collections.unmodifiableList(verifications);
    }

    public Optional<SessionKey> getSessionKey() {
        return sessionKey;
    }

    public List<Verification> getVerifications() {
        return new ArrayList<>(verifications);
    }
}
