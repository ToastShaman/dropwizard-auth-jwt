package com.github.toastshaman.dropwizard.auth.jwt.hmac;

import com.github.toastshaman.dropwizard.auth.jwt.JsonWebTokenVerifier;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebToken;

import static com.github.toastshaman.dropwizard.auth.jwt.JsonWebTokenAlgorithms.HS512;

public class HmacSHA512Verifier extends KeyAware implements JsonWebTokenVerifier {

    private static final String HMAC_SHA512_ALG = "HmacSHA512";

    public HmacSHA512Verifier(byte[] secret) { super(secret, HMAC_SHA512_ALG); }

    @Override
    public String algorithm() { return HS512; }

    @Override
    public boolean verifySignature(JsonWebToken token) { return new HmacVerifier(hmac).verifySignature(token); }
}
