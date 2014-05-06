package com.github.toastshaman.dropwizard.auth.jwt.hmac;

import com.github.toastshaman.dropwizard.auth.jwt.JsonWebTokenSigner;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebToken;

public class HmacSHA384Signer extends KeyAware implements JsonWebTokenSigner {

    private static final String HMAC_SHA384_ALG = "HmacSHA384";

    private static final String JWT_ALG = "HS384";

    public HmacSHA384Signer(byte[] secret) { super(secret, HMAC_SHA384_ALG); }

    @Override
    public String algorithm() { return JWT_ALG; }

    @Override
    public String sign(JsonWebToken token) { return new HmacSigner(hmac).sign(token); }
}
