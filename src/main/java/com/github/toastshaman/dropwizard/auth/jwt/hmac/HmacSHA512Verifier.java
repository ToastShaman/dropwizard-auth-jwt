package com.github.toastshaman.dropwizard.auth.jwt.hmac;

import com.github.toastshaman.dropwizard.auth.jwt.JsonWebTokenVerifier;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebToken;

import static com.github.toastshaman.dropwizard.auth.jwt.JsonWebTokenAlgorithms.HS512;
import static com.google.common.base.Preconditions.checkState;

/**
 * This class can be used to verify the signature of a previously signed bearer token.
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
public class HmacSHA512Verifier extends KeyAware implements JsonWebTokenVerifier {

    private static final String HMAC_SHA512_ALG = "HmacSHA512";

    /**
     * Constructs a bearer token verifier that verifies the signature of a previously signed bearer token.
     * To successfully verify the token's signature it needs to be constructed with the same secret
     * that was used to sign the token.
     * @param secret the secret used to sign the bearer token
     */
    public HmacSHA512Verifier(byte[] secret) {
        super(secret, HMAC_SHA512_ALG);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String algorithm() {
        return HS512;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void verifySignature(JsonWebToken token) {
        checkState(token.header().algorithm().equals(HS512));
        new HmacVerifier(initialiseMac()).verifySignature(token);
    }
}
