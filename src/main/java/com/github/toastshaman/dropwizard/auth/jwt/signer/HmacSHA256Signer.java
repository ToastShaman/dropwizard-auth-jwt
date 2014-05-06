package com.github.toastshaman.dropwizard.auth.jwt.signer;

import com.github.toastshaman.dropwizard.auth.jwt.JWTSigner;
import com.github.toastshaman.dropwizard.auth.jwt.exceptioons.JsonWebTokenException;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebToken;
import com.google.common.base.Joiner;
import com.google.common.io.BaseEncoding;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import static com.google.common.base.Preconditions.checkNotNull;

public class HmacSHA256Signer implements JWTSigner {

    private static final String HMAC_SHA256_ALG = "HmacSHA256";

    private final byte[] secret;

    private SecretKeySpec signingKey;

    private Mac hmac;

    public HmacSHA256Signer(byte[] secret) {
        this.secret = secret;
        initialiseKey(secret);
    }

    private void initialiseKey(byte[] key) {
        this.signingKey = new SecretKeySpec(secret, HMAC_SHA256_ALG);
        try {
            this.hmac = Mac.getInstance(HMAC_SHA256_ALG);
        } catch (NoSuchAlgorithmException e) {
            throw new JsonWebTokenException("cannot use HmacSHA256TokenParser on system without HmacSHA256 algorithm", e);
        }

        try {
            hmac.init(signingKey);
        } catch (InvalidKeyException e) {
            throw new JsonWebTokenException(e.getMessage(), e);
        }
    }

    @Override
    public String algorithm() { return "HS256"; }

    @Override
    public String sign(JsonWebToken token) {
        checkNotNull(token);
        final String jwtPayload = token.deserialize();
        final String signature = encode(hmac.doFinal(jwtPayload.getBytes(Charset.forName("UTF-8"))));
        return Joiner.on(".").join(jwtPayload, signature);
    }

    private String encode(byte[] signature) { return BaseEncoding.base64Url().omitPadding().encode(signature); }
}
