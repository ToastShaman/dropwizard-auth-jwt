package com.github.toastshaman.dropwizard.auth.jwt.model;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.toastshaman.dropwizard.auth.jwt.exceptioons.MalformedJWTTokenException;
import com.google.common.base.Optional;
import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;
import org.apache.commons.lang.StringUtils;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;
import static java.lang.String.format;
import static java.util.Arrays.copyOf;
import static org.apache.commons.lang.StringUtils.isNotBlank;

public class JWTToken {

    private final JWTHeader header;

    private final JWTClaim claim;

    private final byte[] signature;

    private Optional<List<String>> rawToken = Optional.absent();

    public JWTToken(JWTHeader header, JWTClaim claim, byte[] signature) {
        this.header = header;
        this.claim = claim;
        this.signature = copyOf(signature, signature.length);
        this.rawToken = Optional.absent();
    }

    private JWTToken(JWTHeader header, JWTClaim claim, byte[] signature, Optional<List<String>> rawToken) {
        this.header = header;
        this.claim = claim;
        this.signature = copyOf(signature, signature.length);
        this.rawToken = rawToken;
    }

    public JWTHeader getHeader() { return header; }

    public JWTClaim getClaim() { return claim; }

    public byte[] getSignature() { return copyOf(signature, signature.length); }

    public Optional<List<String>> getRawToken() {
        return rawToken;
    }

    public static class Builder {

        private ObjectMapper mapper = new ObjectMapper();

        private JWTHeader header;

        private JWTClaim claim;

        private byte[] signature;

        private Optional<List<String>> rawToken = Optional.absent();

        public JWTToken build() {
            checkNotNull(header);
            checkNotNull(claim);
            checkNotNull(signature);
            checkArgument(signature.length > 0);

            return new JWTToken(header, claim, signature, rawToken);
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

        public Builder claim(String claim) {
            checkArgument(isNotBlank(claim));

            try {
                this.claim = mapper.readValue(claim, JWTClaim.class);
                return this;
            } catch (Exception e) {
                throw new MalformedJWTTokenException(format("The provided JWT claim is malformed: [%s]", claim), e);
            }
        }

        public Builder signature(byte[] signature) {
            checkNotNull(signature);
            checkArgument(signature.length > 0);

            this.signature = signature;
            return this;
        }

        public Builder rawToken(List<String> rawToken) {
            checkNotNull(rawToken);
            checkArgument(rawToken.size() == 3);

            this.rawToken = Optional.of((List<String>) ImmutableList.copyOf(rawToken));
            return this;
        }
    }

    public static Builder builder() { return new Builder(); }
}
