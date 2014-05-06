package com.github.toastshaman.dropwizard.auth.jwt.signer;

public class HmacSHA512Signer extends HmacJsonWebTokenSigner {

    private static final String HMAC_SHA512_ALG = "HmacSHA512";

    public HmacSHA512Signer(byte[] secret) { super(secret); }

    @Override
    String getHmacAlgorithm() { return HMAC_SHA512_ALG; }

    @Override
    public String algorithm() { return "HS512"; }
    
}
