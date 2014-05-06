package com.github.toastshaman.dropwizard.auth.jwt.verifier;

public class HmacSHA256SignatureVerifier extends HmacJsonWebTokenVerifier {

    private static final String HMAC_SHA256_ALG = "HmacSHA256";

    public HmacSHA256SignatureVerifier(byte[] secret) { super(secret); }

    @Override
    String getHmacAlgorithm() { return HMAC_SHA256_ALG; }

    @Override
    public String algorithm() { return "HS256"; }
}
