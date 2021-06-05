package sop;

import java.io.InputStream;
import java.util.List;

public interface VerifySignatures {

    Result<List<Verification>> data(InputStream data);
}
