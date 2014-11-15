package com.github.toastshaman.dropwizard.auth.jwt.exceptions;

public class TokenCreationException extends JsonWebTokenException {

    public TokenCreationException(String message, Throwable t) {
        super(message, t);
    }
}
