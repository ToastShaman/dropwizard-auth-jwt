package com.github.toastshaman.dropwizard.auth.jwt.verifier;

import com.github.toastshaman.dropwizard.auth.jwt.JWTTokenVerifier;
import com.github.toastshaman.dropwizard.auth.jwt.exceptioons.JWTTokenException;
import com.github.toastshaman.dropwizard.auth.jwt.model.JWTToken;
import com.google.common.base.Splitter;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.List;

public class HmacSHA256SignatureVerifier implements JWTTokenVerifier {

    private static final String HMAC_SHA256_ALG = "HmacSHA256";

    private final byte[] secret;

    private SecretKeySpec signingKey;

    private Mac hmac;

    public HmacSHA256SignatureVerifier(byte[] secret) {
        this.secret = secret;
        initialiseKey(secret);
    }

    private void initialiseKey(byte[] key) {
        this.signingKey = new SecretKeySpec(secret, HMAC_SHA256_ALG);
        try {
            this.hmac = Mac.getInstance(HMAC_SHA256_ALG);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("cannot use HmacSHA256TokenParser on system without HmacSHA256 algorithm", e);
        }

        try {
            hmac.init(signingKey);
        } catch (InvalidKeyException e) {
            throw new JWTTokenException(e.getMessage(), e);
        }
    }

    @Override
    public String algorithm() { return "HS256"; }

    @Override
    public boolean verifySignature(JWTToken token, byte[] signature) {
        return false;
    }
}
