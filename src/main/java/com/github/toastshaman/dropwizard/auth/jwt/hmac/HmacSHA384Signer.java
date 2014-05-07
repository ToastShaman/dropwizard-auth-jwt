package com.github.toastshaman.dropwizard.auth.jwt.hmac;

import com.github.toastshaman.dropwizard.auth.jwt.JsonWebTokenSigner;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebToken;

import static com.github.toastshaman.dropwizard.auth.jwt.JsonWebTokenAlgorithms.HS384;

public class HmacSHA384Signer extends KeyAware implements JsonWebTokenSigner {

    private static final String HMAC_SHA384_ALG = "HmacSHA384";

    public HmacSHA384Signer(byte[] secret) { super(secret, HMAC_SHA384_ALG); }

    @Override
    public String algorithm() { return HS384; }

    @Override
    public String sign(JsonWebToken token) { return new HmacSigner(hmac).sign(token); }
}
