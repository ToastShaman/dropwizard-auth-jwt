package com.github.toastshaman.dropwizard.auth.jwt.exceptions;

public class TokenExpiredException extends JsonWebTokenException {

    public TokenExpiredException() {
        super();
    }

    public TokenExpiredException(String msg) {
        super(msg);
    }

    public TokenExpiredException(String msg, Throwable t) {
        super(msg, t);
    }
}
