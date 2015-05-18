package com.github.toastshaman.dropwizard.auth.jwt.exceptions;

public class TokenExpiredException extends JsonWebTokenException {

    public TokenExpiredException() {
        super("The token has expired");
    }
}
