package com.github.toastshaman.dropwizard.auth.jwt.hmac;

import com.github.toastshaman.dropwizard.auth.jwt.JsonWebTokenVerifier;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebToken;

import static com.github.toastshaman.dropwizard.auth.jwt.JsonWebTokenAlgorithms.HS256;

public class HmacSHA256Verifier extends KeyAware implements JsonWebTokenVerifier {

    private static final String HMAC_SHA256_ALG = "HmacSHA256";

    private final HmacVerifier hmacVerifier;

    public HmacSHA256Verifier(byte[] secret) {
        super(secret, HMAC_SHA256_ALG);
        hmacVerifier = new HmacVerifier(hmac);
    }

    @Override
    public String algorithm() { return HS256; }

    @Override
    public void verifySignature(JsonWebToken token) { hmacVerifier.verifySignature(token); }
}
