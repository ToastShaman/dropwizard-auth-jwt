package com.github.toastshaman.dropwizard.auth.jwt.hmac;

public class HmacSHA384Verifier extends HmacVerifier {

    private static final String HMAC_SHA384_ALG = "HmacSHA384";

    public HmacSHA384Verifier(byte[] secret) { super(secret); }

    @Override
    String getHmacAlgorithm() { return HMAC_SHA384_ALG; }

    @Override
    public String algorithm() { return "HS384"; }
}
