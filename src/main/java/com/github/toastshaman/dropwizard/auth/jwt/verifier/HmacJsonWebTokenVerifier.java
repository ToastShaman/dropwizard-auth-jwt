package com.github.toastshaman.dropwizard.auth.jwt.verifier;

import com.github.toastshaman.dropwizard.auth.jwt.JsonWebTokenVerifier;
import com.github.toastshaman.dropwizard.auth.jwt.exceptioons.JsonWebTokenException;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebToken;
import com.google.common.base.Joiner;
import com.google.common.io.BaseEncoding;
import org.apache.commons.lang.StringUtils;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.List;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

public abstract class HmacJsonWebTokenVerifier implements JsonWebTokenVerifier {

    protected final byte[] secret;

    protected SecretKeySpec signingKey;

    protected Mac hmac;

    public HmacJsonWebTokenVerifier(byte[] secret) {
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
    public boolean verifySignature(JsonWebToken token) {
        checkArgument(token.getRawToken().isPresent());
        checkNotNull(token.getSignature());
        checkArgument(token.getSignature().length > 0);

        final String calculatedSignature = encode(calculateSignatureFor(token));
        final String providedSignature = encode(token.getSignature());

        return StringUtils.equals(providedSignature, calculatedSignature);
    }

    private byte[] calculateSignatureFor(JsonWebToken token) {
        final List<String> pieces = token.getRawToken().get();
        return hmac.doFinal(Joiner.on(".").join(pieces.get(0), pieces.get(1)).getBytes(Charset.forName("UTF-8")));
    }

    abstract String getHmacAlgorithm();

    String encode(byte[] signature) { return BaseEncoding.base64Url().omitPadding().encode(signature); }
}
