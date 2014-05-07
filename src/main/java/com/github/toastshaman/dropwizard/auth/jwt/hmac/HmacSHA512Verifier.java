package com.github.toastshaman.dropwizard.auth.jwt.hmac;

import com.github.toastshaman.dropwizard.auth.jwt.JsonWebTokenVerifier;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebToken;

import static com.github.toastshaman.dropwizard.auth.jwt.JsonWebTokenAlgorithms.HS384;
import static com.github.toastshaman.dropwizard.auth.jwt.JsonWebTokenAlgorithms.HS512;
import static com.google.common.base.Preconditions.checkState;

public class HmacSHA512Verifier extends KeyAware implements JsonWebTokenVerifier {

    private static final String HMAC_SHA512_ALG = "HmacSHA512";

    private final HmacVerifier hmacVerifier;

    public HmacSHA512Verifier(byte[] secret) {
        super(secret, HMAC_SHA512_ALG);
        hmacVerifier = new HmacVerifier(hmac);
    }

    @Override
    public String algorithm() { return HS512; }

    @Override
    public void verifySignature(JsonWebToken token) {
        checkState(token.header().alg().equals(HS512));
        hmacVerifier.verifySignature(token);
    }
}
