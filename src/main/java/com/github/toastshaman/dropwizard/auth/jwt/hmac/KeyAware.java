package com.github.toastshaman.dropwizard.auth.jwt.hmac;

import com.github.toastshaman.dropwizard.auth.jwt.exceptions.JsonWebTokenException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;
import static org.apache.commons.lang3.StringUtils.isNotEmpty;

public abstract class KeyAware {

    protected final byte[] secret;

    private final String algorithm;

    /* package */ KeyAware(byte[] secret, String algorithm) {
        checkNotNull(secret);
        checkNotNull(algorithm);
        checkArgument(isNotEmpty(algorithm));

        this.algorithm = algorithm;
        this.secret = secret;
    }

    protected Mac initialiseMac() {
        final SecretKeySpec signingKey = new SecretKeySpec(secret, algorithm);
        try {
            final Mac hmac = Mac.getInstance(algorithm);
            hmac.init(signingKey);
            return hmac;
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new JsonWebTokenException(e.getMessage(), e);
        }
    }
}
