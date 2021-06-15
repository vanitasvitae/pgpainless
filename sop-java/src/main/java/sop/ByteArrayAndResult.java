package sop;

public class ByteArrayAndResult<T> {

    private final byte[] bytes;
    private final T result;

    public ByteArrayAndResult(byte[] bytes, T result) {
        this.bytes = bytes;
        this.result = result;
    }

    public byte[] getBytes() {
        return bytes;
    }

    public T getResult() {
        return result;
    }
}
