package com.github.toastshaman.dropwizard.auth.jwt.exceptions;

public class MalformedJsonWebTokenException extends JsonWebTokenException {

    public MalformedJsonWebTokenException(String msg) {
        super(msg);
    }

    public MalformedJsonWebTokenException(String msg, Throwable t) {
        super(msg, t);
    }
}
