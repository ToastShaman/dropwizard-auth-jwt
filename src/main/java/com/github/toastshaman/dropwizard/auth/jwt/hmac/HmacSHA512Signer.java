package com.github.toastshaman.dropwizard.auth.jwt.hmac;

import com.github.toastshaman.dropwizard.auth.jwt.JsonWebTokenSigner;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebToken;

public class HmacSHA512Signer extends KeyAware implements JsonWebTokenSigner {

    private static final String HMAC_SHA512_ALG = "HmacSHA512";

    private static final String JWT_ALG = "HS512";

    public HmacSHA512Signer(byte[] secret) { super(secret, HMAC_SHA512_ALG); }

    @Override
    public String algorithm() { return JWT_ALG; }

    @Override
    public String sign(JsonWebToken token) { return new HmacSigner(hmac).sign(token); }
}
