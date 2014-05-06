package com.github.toastshaman.dropwizard.auth.jwt.hmac;

import com.github.toastshaman.dropwizard.auth.jwt.JsonWebTokenSigner;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebToken;
import com.google.common.base.Joiner;

import static com.google.common.base.Preconditions.checkNotNull;

public abstract class HmacSigner extends BaseHmacSigner implements JsonWebTokenSigner {

    public HmacSigner(byte[] secret) { super(secret); }

    @Override
    public String sign(JsonWebToken token) {
        checkNotNull(token);
        final String payload = payloadOf(token);
        final String signature = toBase64(sign(bytesOf(payload)));
        return Joiner.on(".").join(payload, signature);
    }

    private String payloadOf(JsonWebToken token) { return token.deserialize(); }

    private byte[] sign(byte[] input) { return hmac.doFinal(input); }
}
