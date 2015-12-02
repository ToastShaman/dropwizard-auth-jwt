package com.github.toastshaman.dropwizard.auth.jwt.model;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.toastshaman.dropwizard.auth.jwt.exceptions.JsonWebTokenException;
import com.github.toastshaman.dropwizard.auth.jwt.exceptions.MalformedJsonWebTokenException;
import com.google.common.base.Joiner;
import com.google.common.base.Optional;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;
import org.apache.commons.lang3.builder.HashCodeBuilder;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

import static com.github.toastshaman.dropwizard.auth.jwt.JsonWebTokenUtils.bytesOf;
import static com.github.toastshaman.dropwizard.auth.jwt.JsonWebTokenUtils.toBase64;
import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.Lists.newArrayList;
import static java.lang.String.format;
import static java.util.Arrays.copyOf;
import static org.apache.commons.lang3.StringUtils.isNotBlank;

/**
 * A JSON Web Token implementation.
 *
 * <pre>{@code
 * &#064;GET
 * &#064;Path("/generate-token")
 * public Map<String, String> generate() {
 *     final HmacSHA512Signer signer = new HmacSHA512Signer(tokenSecret);
 *     final JsonWebToken token = JsonWebToken.builder()
 *         .header(JsonWebTokenHeader.HS512())
 *         .claim(JsonWebTokenClaim.builder()
 *             .subject("joe")
 *             .issuedAt(new DateTime())
 *             .build())
 *         .build();
 *   final String signedToken = signer.sign(token);
 *   return singletonMap("token", signedToken);
 * }
 * }</pre>
 */
public class JsonWebToken {

    private final JsonWebTokenHeader header;

    private final JsonWebTokenClaim claim;

    private byte[] signature;

    private List<String> rawToken;

    private JsonWebToken(JsonWebTokenHeader header, JsonWebTokenClaim claim, byte[] signature, List<String> rawToken) {
        this.header = header;
        this.claim = claim;
        this.signature = signature;
        this.rawToken = Optional.fromNullable(rawToken).or(Lists.<String>newArrayList());
    }

    public JsonWebTokenHeader header() {
        return header;
    }

    public JsonWebTokenClaim claim() {
        return claim;
    }

    public byte[] getSignature() {
        return signature;
    }

    public String deserialize() {
        return Joiner.on(".").join(toBase64(bytesOf(toJson(header))), toBase64(bytesOf(toJson(claim))));
    }

    private String toJson(Object input) {
        try {
            return new ObjectMapper().writeValueAsString(input);
        } catch (IOException e) {
            throw new JsonWebTokenException(e.getMessage(), e);
        }
    }

    public List<String> getRawToken() {
        return rawToken;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        final JsonWebToken that = (JsonWebToken) o;
        return Objects.equals(header, that.header) &&
            Objects.equals(claim, that.claim) &&
            Arrays.equals(signature, that.signature) &&
            Objects.equals(rawToken, that.rawToken);
    }

    @Override
    public int hashCode() {
        return new HashCodeBuilder()
            .append(header)
            .append(claim)
            .append(signature)
            .append(rawToken)
            .hashCode();
    }

    public static class DecoderBuilder {

        private ObjectMapper mapper = new ObjectMapper();

        private JsonWebTokenHeader header;

        private JsonWebTokenClaim claim;

        private byte[] signature = null;

        private List<String> rawToken = newArrayList();

        public JsonWebToken build() {
            checkNotNull(header);
            checkNotNull(claim);
            checkNotNull(rawToken);
            if (signature != null) {
                checkArgument(signature.length > 0);
            }
            if (!rawToken.isEmpty()) {
                checkArgument(rawToken.size() == 3);
            }
            return new JsonWebToken(header, claim, signature, rawToken);
        }

        public DecoderBuilder header(String header) {
            checkArgument(isNotBlank(header));
            try {
                this.header = mapper.readValue(header, JsonWebTokenHeader.class);
                return this;
            } catch (Exception e) {
                throw new MalformedJsonWebTokenException(format("The provided JWT header is malformed: [%s]", header), e);
            }
        }

        public DecoderBuilder claim(String claim) {
            checkArgument(isNotBlank(claim));
            try {
                this.claim = mapper.readValue(claim, JsonWebTokenClaim.class);
                return this;
            } catch (Exception e) {
                throw new MalformedJsonWebTokenException(format("The provided JWT claim is malformed: [%s]", claim), e);
            }
        }

        public DecoderBuilder signature(byte[] signature) {
            checkNotNull(signature);
            checkArgument(signature.length > 0);
            this.signature = copyOf(signature, signature.length);
            return this;
        }

        public DecoderBuilder rawToken(List<String> rawToken) {
            checkNotNull(rawToken);
            checkArgument(rawToken.size() == 3);
            this.rawToken = ImmutableList.copyOf(rawToken);
            return this;
        }
    }

    public static class EncoderBuilder {

        private JsonWebTokenHeader header;

        private JsonWebTokenClaim claim;

        public EncoderBuilder header(JsonWebTokenHeader header) {
            checkNotNull(header);
            this.header = header;
            return this;
        }

        public EncoderBuilder claim(JsonWebTokenClaim claim) {
            checkNotNull(claim);
            this.claim = claim;
            return this;
        }

        public JsonWebToken build() {
            checkNotNull(claim, "can not build a token without a JWT header");
            checkNotNull(header, "can not build a token without a JWT claim");
            return new JsonWebToken(header, claim, null, null);
        }
    }

    public static DecoderBuilder parser() {
        return new DecoderBuilder();
    }

    public static EncoderBuilder builder() {
        return new EncoderBuilder();
    }
}
