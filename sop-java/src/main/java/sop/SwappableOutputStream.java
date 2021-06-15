package sop;

import java.io.IOException;
import java.io.OutputStream;

public class SwappableOutputStream extends OutputStream {

    private OutputStream underlying;

    public SwappableOutputStream(OutputStream underlying) {
        this.underlying = underlying;
    }

    public SwappableOutputStream() {

    }

    public void setUnderlyingStream(OutputStream underlying) {
        if (underlying == null) {
            throw new NullPointerException("Underlying OutputStream cannot be null.");
        }
        this.underlying = underlying;
    }

    @Override
    public void write(byte[] b) throws IOException {
        throwIfUnderlyingStreamIsNull();
        underlying.write(b);
    }

    @Override
    public void write(byte[] b, int off, int len) throws IOException {
        throwIfUnderlyingStreamIsNull();
        underlying.write(b, off, len);
    }

    @Override
    public void flush() throws IOException {
        throwIfUnderlyingStreamIsNull();
        underlying.flush();
    }

    @Override
    public void close() throws IOException {
        throwIfUnderlyingStreamIsNull();
        underlying.close();
    }

    @Override
    public void write(int i) throws IOException {
        throwIfUnderlyingStreamIsNull();
        underlying.write(i);
    }

    private void throwIfUnderlyingStreamIsNull() throws IOException {
        if (underlying == null) {
            throw new IOException("Underlying OutputStream is null.");
        }
    }
}
