package com.github.toastshaman.dropwizard.auth.jwt.hmac;

import com.github.toastshaman.dropwizard.auth.jwt.JsonWebTokenVerifier;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebToken;

import static com.github.toastshaman.dropwizard.auth.jwt.JsonWebTokenAlgorithms.HS384;
import static com.google.common.base.Preconditions.checkArgument;

/**
 * This class can be used to verify the signature of a previously signed bearer token.
 *
 * <pre>{@code
 * final String encodedToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzM4NCJ9"
 *     + ".eyJpc3MiOiJqb2UiLCJleHAiOm51bGx9"
 *     + ".yS0gHKcZXzOd5rR1v9g7WMOyv-TML_eDwxY_pk2NBvivoYk3YibsRk_zL9YUauJI";
 *
 * final byte[] key = bytesOf("SECRET");
 * final JsonWebToken token = new DefaultJsonWebTokenParser().parse(encodedToken);
 * final HmacSHA384Verifier verifier = new HmacSHA384Verifier(key);
 * verifier.verifySignature(token);
 *}</pre>
 */
public class HmacSHA384Verifier extends KeyAware implements JsonWebTokenVerifier {

    private static final String HMAC_SHA384_ALG = "HmacSHA384";

    /**
     * Constructs a bearer token verifier that verifies the signature of a previously signed bearer token.
     * To successfully verify the token's signature it needs to be constructed with the same secret
     * that was used to sign the token.
     * @param secret the secret used to sign the bearer token
     */
    public HmacSHA384Verifier(byte[] secret) {
        super(secret, HMAC_SHA384_ALG);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String algorithm() {
        return HS384;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void verifySignature(JsonWebToken token) {
        checkArgument(token.header().algorithm().equals(HS384), "Can not verify a %s with a %s verifier", token.header().algorithm(), HS384);
        new HmacVerifier(initialiseMac()).verifySignature(token);
    }
}
