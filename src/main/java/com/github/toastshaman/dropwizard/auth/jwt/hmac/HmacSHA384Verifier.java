package com.github.toastshaman.dropwizard.auth.jwt.hmac;

import com.github.toastshaman.dropwizard.auth.jwt.JsonWebTokenVerifier;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebToken;

import static com.github.toastshaman.dropwizard.auth.jwt.JsonWebTokenAlgorithms.HS384;

public class HmacSHA384Verifier extends KeyAware implements JsonWebTokenVerifier {

    private static final String HMAC_SHA384_ALG = "HmacSHA384";

    private final HmacVerifier hmacVerifier;

    public HmacSHA384Verifier(byte[] secret) {
        super(secret, HMAC_SHA384_ALG);
        hmacVerifier = new HmacVerifier(hmac);
    }

    @Override
    public String algorithm() { return HS384; }

    @Override
    public void verifySignature(JsonWebToken token) { hmacVerifier.verifySignature(token); }
}
