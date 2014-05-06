package com.github.toastshaman.dropwizard.auth.jwt.hmac;

import com.github.toastshaman.dropwizard.auth.jwt.JsonWebTokenSigner;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebToken;
import com.google.common.base.Joiner;

import java.nio.charset.Charset;

import static com.google.common.base.Preconditions.checkNotNull;

public abstract class HmacSigner extends BaseHmacSigner implements JsonWebTokenSigner {

    public HmacSigner(byte[] secret) { super(secret); }

    @Override
    public String sign(JsonWebToken token) {
        checkNotNull(token);
        final String jwtPayload = token.deserialize();
        final String signature = encode(hmac.doFinal(jwtPayload.getBytes(Charset.forName("UTF-8"))));
        return Joiner.on(".").join(jwtPayload, signature);
    }
}
