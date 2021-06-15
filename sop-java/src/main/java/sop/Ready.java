package sop;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

public abstract class Ready {

    public abstract void writeTo(OutputStream outputStream) throws IOException;

    public byte[] getBytes() throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        writeTo(bytes);
        return bytes.toByteArray();
    }
}
