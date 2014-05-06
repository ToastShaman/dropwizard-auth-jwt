package com.github.toastshaman.dropwizard.auth.jwt.verifier;

public class HmacSHA384SignatureVerifier extends HmacJsonWebTokenVerifier {

    private static final String HMAC_SHA384_ALG = "HmacSHA384";

    public HmacSHA384SignatureVerifier(byte[] secret) { super(secret); }

    @Override
    String getHmacAlgorithm() { return HMAC_SHA384_ALG; }

    @Override
    public String algorithm() { return "HS384"; }
}
