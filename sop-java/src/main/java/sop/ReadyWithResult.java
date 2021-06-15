package sop;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;

public abstract class ReadyWithResult<T> {

    public abstract T writeTo(OutputStream outputStream);

    public ByteArrayAndResult<T> toBytes() {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        T result = writeTo(bytes);
        return new ByteArrayAndResult<>(bytes.toByteArray(), result);
    }
}
