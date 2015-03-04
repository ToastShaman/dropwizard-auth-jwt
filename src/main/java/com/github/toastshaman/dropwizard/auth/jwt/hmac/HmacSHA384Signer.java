package com.github.toastshaman.dropwizard.auth.jwt.hmac;

import com.github.toastshaman.dropwizard.auth.jwt.JsonWebTokenSigner;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebToken;

import static com.github.toastshaman.dropwizard.auth.jwt.JsonWebTokenAlgorithms.HS384;
import static com.google.common.base.Preconditions.checkArgument;

/**
 * This class can be used to sign a newly created bearer token with a HMAC (SHA-384).
 *
 * <pre>{@code
 * final HmacSHA384Signer signer = new HmacSHA384Signer(bytesOf("SECRET"));
 * final JsonWebToken token = JsonWebToken.builder()
 *     .header(JsonWebTokenHeader.HS384())
 *     .claim(JsonWebTokenClaim.builder().subject("joe").build())
 *     .build();
 *
 * final String signedToken = signer.sign(token);
 * }</pre>
 */
public class HmacSHA384Signer extends KeyAware implements JsonWebTokenSigner {

    private static final String HMAC_SHA384_ALG = "HmacSHA384";

    public HmacSHA384Signer(byte[] secret) {
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
    public String sign(JsonWebToken token) {
        checkArgument(token.header().algorithm().equals(HS384), "Can not sign a %s with a %s signer", token.header().algorithm(), HS384);
        return new HmacSigner(initialiseMac()).sign(token);
    }
}
