package com.github.toastshaman.dropwizard.auth.jwt.verifier;

public class HmacSHA512SignatureVerifier extends HmacJsonWebTokenVerifier {

    private static final String HMAC_SHA512_ALG = "HmacSHA512";

    public HmacSHA512SignatureVerifier(byte[] secret) { super(secret); }

    @Override
    String getHmacAlgorithm() { return HMAC_SHA512_ALG; }

    @Override
    public String algorithm() { return "HS512"; }
}
