package com.github.toastshaman.dropwizard.auth.jwt.hmac;

public class HmacSHA512Verifier extends HmacVerifier {

    private static final String HMAC_SHA512_ALG = "HmacSHA512";

    private static final String JWT_ALG = "HS512";

    public HmacSHA512Verifier(byte[] secret) { super(secret); }

    @Override
    String getSignatureAlgorithm() { return HMAC_SHA512_ALG; }

    @Override
    public String algorithm() { return JWT_ALG; }
}
