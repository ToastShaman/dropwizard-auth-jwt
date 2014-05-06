package com.github.toastshaman.dropwizard.auth.jwt.hmac;

public class HmacSHA256Verifier extends HmacVerifier {

    private static final String HMAC_SHA256_ALG = "HmacSHA256";

    private static final String JWT_ALG = "HS256";

    public HmacSHA256Verifier(byte[] secret) { super(secret); }

    @Override
    String getSignatureAlgorithm() { return HMAC_SHA256_ALG; }

    @Override
    public String algorithm() { return JWT_ALG; }
}
