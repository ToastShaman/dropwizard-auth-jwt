package com.github.toastshaman.dropwizard.auth.jwt;

import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebToken;

/**
 * Used for classes that want to validate bearer tokens after the signature has been successfully verified.
 * An example of such a validator would be the @see ExpiryValidator that verifies that the token did not
 * exceed it's expiry time.
 */
public interface JsonWebTokenValidator {

    /**
     * Validates claims attached to the bearer token such as expiry time etc.
     * Throws a runtime exception in case of the token being invalid.
     * @throws com.github.toastshaman.dropwizard.auth.jwt.exceptions.JsonWebTokenException
     * @param token the token to verify
     */
    void validate(JsonWebToken token);
}
