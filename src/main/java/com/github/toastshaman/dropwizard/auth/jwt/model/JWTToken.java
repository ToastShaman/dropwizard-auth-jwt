package com.github.toastshaman.dropwizard.auth.jwt.model;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.toastshaman.dropwizard.auth.jwt.exceptioons.MalformedJWTTokenException;
import com.google.common.base.Preconditions;
import org.apache.commons.lang.StringUtils;

import java.io.IOException;
import java.util.Arrays;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;
import static java.lang.String.format;
import static java.util.Arrays.copyOf;
import static org.apache.commons.lang.StringUtils.isNotBlank;

public class JWTToken {

    private final JWTHeader header;

    private final JWTClaim claim;

    private final byte[] signature;

    public JWTToken(JWTHeader header, JWTClaim claim, byte[] signature) {
        this.header = header;
        this.claim = claim;
        this.signature = copyOf(signature, signature.length);
    }

    public JWTHeader getHeader() { return header; }

    public JWTClaim getClaim() { return claim; }

    public byte[] getSignature() { return copyOf(signature, signature.length); }

    public static class Builder {

        private ObjectMapper mapper = new ObjectMapper();

        private JWTHeader header;

        private JWTClaim claim;

        private byte[] signature;

        public JWTToken build() {
            checkNotNull(header);
            checkNotNull(claim);
            checkNotNull(signature);
            checkArgument(signature.length > 0);

            return new JWTToken(header, claim, signature);
        }

        public Builder header(String header) {
            checkArgument(isNotBlank(header));

            try {
                this.header = mapper.readValue(header, JWTHeader.class);
                return this;
            } catch (Exception e) {
                throw new MalformedJWTTokenException(format("The provided JWT header is malformed: [%s]", header), e);
            }
        }

        public Builder signature(byte[] signature) {
            checkNotNull(signature);
            checkArgument(signature.length > 0);

            this.signature = signature;
            return this;
        }

        public Builder claim(String claim) {
            checkArgument(isNotBlank(claim));

            try {
                this.claim = mapper.readValue(claim, JWTClaim.class);
                return this;
            } catch (Exception e) {
                throw new MalformedJWTTokenException(format("The provided JWT claim is malformed: [%s]", claim), e);
            }
        }
    }

    public static Builder builder() { return new Builder(); }
}
