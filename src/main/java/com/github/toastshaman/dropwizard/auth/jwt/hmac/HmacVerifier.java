package com.github.toastshaman.dropwizard.auth.jwt.hmac;

import com.github.toastshaman.dropwizard.auth.jwt.JsonWebTokenVerifier;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebToken;
import com.google.common.base.Joiner;
import org.apache.commons.lang.StringUtils;

import java.util.List;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

public abstract class HmacVerifier extends BaseHmacSigner implements JsonWebTokenVerifier {

    public HmacVerifier(byte[] secret) { super(secret); }

    @Override
    public boolean verifySignature(JsonWebToken token) {
        checkArgument(token.getRawToken().isPresent());
        checkNotNull(token.getSignature());
        checkArgument(token.getSignature().length > 0);

        final String calculatedSignature = toBase64(calculateSignatureFor(token));
        final String providedSignature = toBase64(token.getSignature());

        return StringUtils.equals(providedSignature, calculatedSignature);
    }

    private byte[] calculateSignatureFor(JsonWebToken token) {
        final List<String> pieces = token.getRawToken().get();
        return hmac.doFinal(bytesOf(concatenate(pieces)));
    }

    private String concatenate(List<String> pieces) { return Joiner.on(".").join(pieces.get(0), pieces.get(1)); }

}
