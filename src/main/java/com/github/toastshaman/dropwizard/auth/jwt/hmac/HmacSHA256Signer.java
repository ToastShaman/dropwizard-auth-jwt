package com.github.toastshaman.dropwizard.auth.jwt.hmac;

public class HmacSHA256Signer extends HmacSigner {

    private static final String HMAC_SHA256_ALG = "HmacSHA256";

    public HmacSHA256Signer(byte[] secret) { super(secret); }

    @Override
    String getHmacAlgorithm() { return HMAC_SHA256_ALG; }

    @Override
    public String algorithm() { return "HS256"; }
}