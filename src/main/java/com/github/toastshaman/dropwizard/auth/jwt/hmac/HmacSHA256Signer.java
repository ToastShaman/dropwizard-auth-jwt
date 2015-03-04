package com.github.toastshaman.dropwizard.auth.jwt.hmac;

import com.github.toastshaman.dropwizard.auth.jwt.JsonWebTokenSigner;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebToken;

import static com.github.toastshaman.dropwizard.auth.jwt.JsonWebTokenAlgorithms.HS256;
import static com.google.common.base.Preconditions.checkArgument;

/**
 * This class can be used to sign a newly created bearer token with a HMAC (SHA-256).
 *
 * <pre>{@code
 * final HmacSHA256Signer signer = new HmacSHA256Signer(bytesOf("SECRET"));
 * final JsonWebToken token = JsonWebToken.builder()
 *     .header(JsonWebTokenHeader.HS256())
 *     .claim(JsonWebTokenClaim.builder().subject("joe").build())
 *     .build();
 *
 * final String signedToken = signer.sign(token);
 * }</pre>
 */
public class HmacSHA256Signer extends KeyAware implements JsonWebTokenSigner {

    private static final String HMAC_SHA256_ALG = "HmacSHA256";

    /**
     * Constructs a signer that signs a previously created token.
     * @param secret the secret that will be used to sign the bearer token
     */
    public HmacSHA256Signer(byte[] secret) {
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
    public String sign(JsonWebToken token) {
        checkArgument(token.header().algorithm().equals(HS256), "Can not sign a %s with a %s signer", token.header().algorithm(), HS256);
        return new HmacSigner(initialiseMac()).sign(token);
    }
}
