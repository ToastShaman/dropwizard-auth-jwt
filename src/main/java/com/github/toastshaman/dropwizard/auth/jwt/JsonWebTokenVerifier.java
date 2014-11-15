package com.github.toastshaman.dropwizard.auth.jwt;

import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebToken;

/**
 * Used for classes that verify the validity of a bearer token's signature.
 */
public interface JsonWebTokenVerifier {

    /**
     * @return the name of the secret-key algorithm to be associated with the given key material.
     * See Appendix A in the Java <a href="https://docs.oracle.com/javase/7/docs/technotes/guides/security/crypto/CryptoSpec.html#AppA">Cryptography
     * Architecture Reference Guide</a> for information about standard algorithm names.
     */
    String algorithm();

    /**
     * Verifies the signature of the provided bearer token and throws a runtime exception if the signature is invalid.
     * @param token the token to validate
     * @throws com.github.toastshaman.dropwizard.auth.jwt.exceptions.InvalidSignatureException if the signatures do not match
     */
    void verifySignature(JsonWebToken token);
}
