package com.github.toastshaman.dropwizard.auth.jwt.hmac;

import com.github.toastshaman.dropwizard.auth.jwt.JsonWebTokenSigner;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebToken;

import static com.github.toastshaman.dropwizard.auth.jwt.JsonWebTokenAlgorithms.HS512;

public class HmacSHA512Signer extends KeyAware implements JsonWebTokenSigner {

    private static final String HMAC_SHA512_ALG = "HmacSHA512";

    private final HmacSigner hmacSigner;

    public HmacSHA512Signer(byte[] secret) {
        super(secret, HMAC_SHA512_ALG);
        hmacSigner = new HmacSigner(hmac);
    }

    @Override
    public String algorithm() { return HS512; }

    @Override
    public String sign(JsonWebToken token) { return hmacSigner.sign(token); }
}
