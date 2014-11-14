package com.github.toastshaman.dropwizard.auth.jwt.exceptions;

/**
 * Thrown if the provided {@code JsonWebToken}'s signature is not valid.
 * This usually happens when a client sends a token that has not been
 * generated on this server.
 */
public class InvalidSignatureException extends JsonWebTokenException {

    public InvalidSignatureException() {
        super();
    }
}
