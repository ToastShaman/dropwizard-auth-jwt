package com.github.toastshaman.dropwizard.auth.jwt.hmac;

import com.github.toastshaman.dropwizard.auth.jwt.JsonWebTokenVerifier;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebToken;

import static com.github.toastshaman.dropwizard.auth.jwt.JsonWebTokenAlgorithms.HS256;
import static com.google.common.base.Preconditions.checkArgument;

/**
 * This class can be used to verify the signature of a previously signed bearer token.
 *
 * <pre>{@code
 * private final String encodedToken = ""
 *     + "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9"
 *     + ".eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
 *     + ".dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
 *
 * final byte[] key = bytesOf("SECRET");
 * final JsonWebToken token = new DefaultJsonWebTokenParser().parse(encodedToken);
 * final HmacSHA256Verifier verifier = new HmacSHA256Verifier(key);
 * verifier.verifySignature(token);
 *}</pre>
 */
public class HmacSHA256Verifier extends KeyAware implements JsonWebTokenVerifier {

    private static final String HMAC_SHA256_ALG = "HmacSHA256";

    /**
     * Constructs a bearer token verifier that verifies the signature of a previously signed bearer token.
     * To successfully verify the token's signature it needs to be constructed with the same secret
     * that was used to sign the token.
     * @param secret the secret used to sign the bearer token
     */
    public HmacSHA256Verifier(byte[] secret) {
        super(secret, HMAC_SHA256_ALG);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String algorithm() {
        return HS256;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void verifySignature(JsonWebToken token) {
        checkArgument(token.header().algorithm().equals(HS256), "Can not verify a %s with a %s verifier", token.header().algorithm(), HS256);
        new HmacVerifier(initialiseMac()).verifySignature(token);
    }
}
