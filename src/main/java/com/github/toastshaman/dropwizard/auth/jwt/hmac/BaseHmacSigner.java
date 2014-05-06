package com.github.toastshaman.dropwizard.auth.jwt.hmac;

import com.github.toastshaman.dropwizard.auth.jwt.exceptioons.JsonWebTokenException;
import com.google.common.io.BaseEncoding;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import static com.google.common.base.Preconditions.checkNotNull;

public abstract class BaseHmacSigner {

    protected final byte[] secret;

    protected SecretKeySpec signingKey;

    protected Mac hmac;

    public BaseHmacSigner(byte[] secret) {
        checkNotNull(secret);
        this.secret = secret;
        initialiseKey(secret);
    }

    private void initialiseKey(byte[] key) {
        this.signingKey = new SecretKeySpec(secret, getSignatureAlgorithm());
        try {
            this.hmac = Mac.getInstance(getSignatureAlgorithm());
        } catch (NoSuchAlgorithmException e) {
            throw new JsonWebTokenException(e.getMessage(), e);
        }

        try {
            hmac.init(signingKey);
        } catch (InvalidKeyException e) {
            throw new JsonWebTokenException(e.getMessage(), e);
        }
    }

    abstract String getSignatureAlgorithm();

    String toBase64(byte[] signature) { return BaseEncoding.base64Url().omitPadding().encode(signature); }
}
