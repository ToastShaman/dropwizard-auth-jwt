package com.github.toastshaman.dropwizard.auth.jwt;

import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebToken;

/**
 * Used for classes that verify the validity of a bearer token's signature.
 *
 * <pre>{@code
 * final String encodedToken = ""
 *     + "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9"
 *     + ".eyJpc3MiOiJqb2UiLCJleHAiOm51bGx9"
 *     + ".JFtrDyI2ODV5I_aVfX7BnIClMqXi2SEDbRI2XTL2fV6veWICptkPi6OUJUHhSP9v_7rX8brgHJn-gbDmla_aEw";
 *
 * final byte[] key = bytesOf("SECRET");
 * final JsonWebToken token = new DefaultJsonWebTokenParser().parse(encodedToken);
 * final HmacSHA512Verifier verifier = new HmacSHA512Verifier(key);
 * verifier.verifySignature(token);
 *}</pre>
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
     */
    void verifySignature(JsonWebToken token);
}
