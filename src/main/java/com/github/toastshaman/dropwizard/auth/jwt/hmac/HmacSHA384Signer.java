package com.github.toastshaman.dropwizard.auth.jwt.hmac;

public class HmacSHA384Signer extends HmacSigner {

    private static final String HMAC_SHA384_ALG = "HmacSHA384";

    public HmacSHA384Signer(byte[] secret) { super(secret); }

    @Override
    String getHmacAlgorithm() { return HMAC_SHA384_ALG; }

    @Override
    public String algorithm() { return "HS384"; }
}
