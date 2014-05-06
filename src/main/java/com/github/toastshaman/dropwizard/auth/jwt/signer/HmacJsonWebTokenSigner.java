package com.github.toastshaman.dropwizard.auth.jwt.signer;

import com.github.toastshaman.dropwizard.auth.jwt.JsonWebTokenSigner;
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

public abstract class HmacJsonWebTokenSigner implements JsonWebTokenSigner {

    protected final byte[] secret;

    protected SecretKeySpec signingKey;

    protected Mac hmac;

    public HmacJsonWebTokenSigner(byte[] secret) {
        checkNotNull(secret);
        this.secret = secret;
        initialiseKey(secret);
    }

    private void initialiseKey(byte[] key) {
        this.signingKey = new SecretKeySpec(secret, getHmacAlgorithm());
        try {
            this.hmac = Mac.getInstance(getHmacAlgorithm());
        } catch (NoSuchAlgorithmException e) {
            throw new JsonWebTokenException(e.getMessage(), e);
        }

        try {
            hmac.init(signingKey);
        } catch (InvalidKeyException e) {
            throw new JsonWebTokenException(e.getMessage(), e);
        }
    }

    @Override
    public String sign(JsonWebToken token) {
        checkNotNull(token);
        final String jwtPayload = token.deserialize();
        final String signature = encode(hmac.doFinal(jwtPayload.getBytes(Charset.forName("UTF-8"))));
        return Joiner.on(".").join(jwtPayload, signature);
    }

    protected String encode(byte[] signature) { return BaseEncoding.base64Url().omitPadding().encode(signature); }

    abstract String getHmacAlgorithm();
}
