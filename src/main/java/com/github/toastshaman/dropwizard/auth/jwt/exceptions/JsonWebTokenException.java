package com.github.toastshaman.dropwizard.auth.jwt.exceptions;

public class JsonWebTokenException extends RuntimeException {

    public JsonWebTokenException() {
        super();
    }

    public JsonWebTokenException(String msg) {
        super(msg);
    }

    public JsonWebTokenException(String msg, Throwable t) {
        super(msg, t);
    }
}
