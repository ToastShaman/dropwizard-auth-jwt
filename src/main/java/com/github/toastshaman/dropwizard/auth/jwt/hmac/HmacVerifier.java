package com.github.toastshaman.dropwizard.auth.jwt.hmac;

import com.github.toastshaman.dropwizard.auth.jwt.exceptions.InvalidSignatureException;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebToken;
import com.google.common.base.Joiner;

import javax.crypto.Mac;
import java.util.Arrays;
import java.util.List;

import static com.github.toastshaman.dropwizard.auth.jwt.JsonWebTokenUtils.bytesOf;
import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

public class HmacVerifier {

    private final Mac hmac;

    /* package */ HmacVerifier(Mac hmac) {
        this.hmac = hmac;
    }

    public void verifySignature(JsonWebToken token) {
        checkArgument(token.getRawToken().isPresent());
        checkNotNull(token.getSignature());
        checkArgument(token.getSignature().length > 0);

        final byte[] calculatedSignature = calculateSignatureFor(token);
        final byte[] providedSignature = token.getSignature();

        if (!Arrays.equals(calculatedSignature, providedSignature)) {
            throw new InvalidSignatureException();
        }
    }

    private byte[] calculateSignatureFor(JsonWebToken token) {
        final List<String> pieces = token.getRawToken().get();
        return hmac.doFinal(bytesOf(concatenate(pieces)));
    }

    private String concatenate(List<String> pieces) {
        return Joiner.on(".").join(pieces.get(0), pieces.get(1));
    }

}
