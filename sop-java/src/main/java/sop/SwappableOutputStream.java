/*
 * Copyright 2021 Paul Schaub.
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
package sop;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

public class SwappableOutputStream extends OutputStream {

    private OutputStream underlying;

    public SwappableOutputStream(OutputStream underlying) {
        this.underlying = underlying;
    }

    public SwappableOutputStream() {
        this(new ByteArrayOutputStream());
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
