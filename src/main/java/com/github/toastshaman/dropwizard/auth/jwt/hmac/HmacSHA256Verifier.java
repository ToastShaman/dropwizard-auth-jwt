package com.github.toastshaman.dropwizard.auth.jwt.hmac;

import com.github.toastshaman.dropwizard.auth.jwt.JsonWebTokenVerifier;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebToken;

public class HmacSHA256Verifier extends KeyAware implements JsonWebTokenVerifier {

    private static final String HMAC_SHA256_ALG = "HmacSHA256";

    private static final String JWT_ALG = "HS256";

    public HmacSHA256Verifier(byte[] secret) { super(secret, HMAC_SHA256_ALG); }

    @Override
    public String algorithm() { return JWT_ALG; }

    @Override
    public boolean verifySignature(JsonWebToken token) { return new HmacVerifier(hmac).verifySignature(token); }
}
