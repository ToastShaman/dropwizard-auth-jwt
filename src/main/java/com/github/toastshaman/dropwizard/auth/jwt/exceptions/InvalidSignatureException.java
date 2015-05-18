package com.github.toastshaman.dropwizard.auth.jwt.exceptions;

public class InvalidSignatureException extends JsonWebTokenException {

    public InvalidSignatureException() {
        super("The token's signature is invalid");
    }
}
