package com.github.toastshaman.dropwizard.auth.jwt.hmac;

import com.github.toastshaman.dropwizard.auth.jwt.exceptions.JsonWebTokenException;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebToken;
import com.google.common.base.Joiner;
import org.apache.commons.lang.StringUtils;

import javax.crypto.Mac;
import java.util.List;

import static com.github.toastshaman.dropwizard.auth.jwt.JsonWebTokenUtils.bytesOf;
import static com.github.toastshaman.dropwizard.auth.jwt.JsonWebTokenUtils.toBase64;
import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

public class HmacVerifier {

    private final Mac hmac;

    public HmacVerifier(Mac hmac) { this.hmac = hmac; }

    public boolean verifySignature(JsonWebToken token) {
        checkArgument(token.getRawToken().isPresent());
        checkNotNull(token.getSignature());
        checkArgument(token.getSignature().length > 0);

        final String calculatedSignature = toBase64(calculateSignatureFor(token));
        final String providedSignature = toBase64(token.getSignature());

        return StringUtils.equals(providedSignature, calculatedSignature);
    }

    private byte[] calculateSignatureFor(JsonWebToken token) {
        if (token.getRawToken().isPresent()) {
            final List<String> pieces = token.getRawToken().get();
            return hmac.doFinal(bytesOf(concatenate(pieces)));
        }
        throw new JsonWebTokenException("Signature can not be verified because the given token does not provide one.");
    }

    private String concatenate(List<String> pieces) { return Joiner.on(".").join(pieces.get(0), pieces.get(1)); }

}
