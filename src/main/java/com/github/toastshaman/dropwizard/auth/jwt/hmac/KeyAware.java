package com.github.toastshaman.dropwizard.auth.jwt.hmac;

import com.github.toastshaman.dropwizard.auth.jwt.exceptioons.JsonWebTokenException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;
import static org.apache.commons.lang.StringUtils.isNotEmpty;

public abstract class KeyAware {

    protected final byte[] secret;

    private final String algorithm;

    protected SecretKeySpec signingKey;

    protected Mac hmac;

    public KeyAware(byte[] secret, String algorithm) {
        checkNotNull(secret);
        checkNotNull(algorithm);
        checkArgument(isNotEmpty(algorithm));

        this.algorithm = algorithm;
        this.secret = secret;
        initialiseKey(secret);
    }

    private void initialiseKey(byte[] key) {
        this.signingKey = new SecretKeySpec(secret, algorithm);
        try {
            this.hmac = Mac.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new JsonWebTokenException(e.getMessage(), e);
        }

        try {
            hmac.init(signingKey);
        } catch (InvalidKeyException e) {
            throw new JsonWebTokenException(e.getMessage(), e);
        }
    }
}
