package com.github.toastshaman.dropwizard.auth.jwt;

import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebToken;

/**
 * Used for classes that want to sign a newly created bearer token.
 */
public interface JsonWebTokenSigner {

    /**
     * @return the name of the secret-key algorithm to be associated with the given key material.
     * See Appendix A in the Java <a href="https://docs.oracle.com/javase/7/docs/technotes/guides/security/crypto/CryptoSpec.html#AppA">Cryptography
     * Architecture Reference Guide</a> for information about standard algorithm names.
     */
    String algorithm();

    /**
     * Signs a given bearer token and it's enclosed claims.
     * @param token the token to sign
     * @return a string representing a set of claims that have been digitally signed or MACed
     */
    String sign(JsonWebToken token);
}
