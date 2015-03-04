package com.github.toastshaman.dropwizard.auth.jwt.hmac;

import com.github.toastshaman.dropwizard.auth.jwt.JsonWebTokenSigner;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebToken;

import static com.github.toastshaman.dropwizard.auth.jwt.JsonWebTokenAlgorithms.HS512;
import static com.google.common.base.Preconditions.checkArgument;

/**
 * This class can be used to sign a newly created bearer token with a HMAC (SHA-512).
 *
 * <pre>{@code
 * final HmacSHA512Signer signer = new HmacSHA512Signer(bytesOf("SECRET"));
 * final JsonWebToken token = JsonWebToken.builder()
 *     .header(JsonWebTokenHeader.HS512())
 *     .claim(JsonWebTokenClaim.builder().subject("joe").build())
 *     .build();
 *
 * final String signedToken = signer.sign(token);
 * }</pre>
 */
public class HmacSHA512Signer extends KeyAware implements JsonWebTokenSigner {

    private static final String HMAC_SHA512_ALG = "HmacSHA512";

    public HmacSHA512Signer(byte[] secret) {
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
    public String sign(JsonWebToken token) {
        checkArgument(token.header().algorithm().equals(HS512), "Can not sign a %s with a %s signer", token.header().algorithm(), HS512);
        return new HmacSigner(initialiseMac()).sign(token);
    }
}
