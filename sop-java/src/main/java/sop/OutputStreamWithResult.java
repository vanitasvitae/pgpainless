package sop;

import java.io.OutputStream;

public abstract class OutputStreamWithResult<T> extends OutputStream {

    

    abstract Result<T> getResult();
}
