package com.github.toastshaman.dropwizard.auth.jwt.hmac;

import com.github.toastshaman.dropwizard.auth.jwt.JsonWebTokenSigner;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebToken;

import static com.github.toastshaman.dropwizard.auth.jwt.JsonWebTokenAlgorithms.HS256;

public class HmacSHA256Signer extends KeyAware implements JsonWebTokenSigner {

    private static final String HMAC_SHA256_ALG = "HmacSHA256";

    private final HmacSigner hmacSigner;

    public HmacSHA256Signer(byte[] secret) {
        super(secret, HMAC_SHA256_ALG);
        hmacSigner = new HmacSigner(hmac);
    }

    @Override
    public String algorithm() { return HS256; }

    @Override
    public String sign(JsonWebToken token) { return hmacSigner.sign(token); }
}
