package com.github.toastshaman.dropwizard.auth.jwt.hmac;

import com.github.toastshaman.dropwizard.auth.jwt.JsonWebTokenAlgorithms;
import com.github.toastshaman.dropwizard.auth.jwt.JsonWebTokenVerifier;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebToken;

import static com.github.toastshaman.dropwizard.auth.jwt.JsonWebTokenAlgorithms.HS384;
import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkState;

public class HmacSHA384Verifier extends KeyAware implements JsonWebTokenVerifier {

    private static final String HMAC_SHA384_ALG = "HmacSHA384";

    private final HmacVerifier hmacVerifier;

    public HmacSHA384Verifier(byte[] secret) {
        super(secret, HMAC_SHA384_ALG);
        hmacVerifier = new HmacVerifier(hmac);
    }

    @Override
    public String algorithm() {
        return HS384;
    }

    @Override
    public void verifySignature(JsonWebToken token) {
        checkArgument(token.header().alg().equals(HS384), "Can not verify a %s with a %s verifier", token.header().alg(), HS384);
        hmacVerifier.verifySignature(token);
    }
}
