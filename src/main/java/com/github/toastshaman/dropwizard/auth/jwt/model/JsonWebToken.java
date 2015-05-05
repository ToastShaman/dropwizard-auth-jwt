package com.github.toastshaman.dropwizard.auth.jwt.model;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.toastshaman.dropwizard.auth.jwt.exceptions.JsonWebTokenException;
import com.github.toastshaman.dropwizard.auth.jwt.exceptions.MalformedJsonWebTokenException;
import com.google.common.base.Joiner;
import com.google.common.base.Optional;
import com.google.common.collect.ImmutableList;

import java.io.IOException;
import java.io.StringWriter;
import java.util.List;

import static com.github.toastshaman.dropwizard.auth.jwt.JsonWebTokenUtils.bytesOf;
import static com.github.toastshaman.dropwizard.auth.jwt.JsonWebTokenUtils.toBase64;
import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;
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

    private Optional<byte[]> signature;

    private Optional<List<String>> rawToken = Optional.absent();

    private JsonWebToken(JsonWebTokenHeader header, JsonWebTokenClaim claim, Optional<byte[]> signature, Optional<List<String>> rawToken) {
        this.header = header;
        this.claim = claim;
        this.signature = signature;
        this.rawToken = rawToken;
    }

    public JsonWebTokenHeader header() {
        return header;
    }

    public JsonWebTokenClaim claim() {
        return claim;
    }

    public byte[] getSignature() {
        return signature.orNull();
    }

    public String deserialize() {
        return Joiner.on(".").join(toBase64(bytesOf(toJson(header))), toBase64(bytesOf(toJson(claim))));
    }

    private String toJson(Object input) {
        try {
            ObjectMapper mapper = new ObjectMapper();
            StringWriter output = new StringWriter();
            mapper.writeValue(output, input);
            return output.toString();
        } catch (IOException e) {
            throw new JsonWebTokenException(e.getMessage(), e);
        }
    }

    public Optional<List<String>> getRawToken() {
        return rawToken;
    }

    public static class DecoderBuilder {

        private ObjectMapper mapper = new ObjectMapper();

        private JsonWebTokenHeader header;

        private JsonWebTokenClaim claim;

        private Optional<byte[]> signature = Optional.absent();

        private Optional<List<String>> rawToken = Optional.absent();

        public JsonWebToken build() {
            checkNotNull(header);
            checkNotNull(claim);
            checkNotNull(rawToken);
            if (signature.isPresent()) {
                checkArgument(signature.get().length > 0);
            }
            if (rawToken.isPresent()) {
                checkArgument(rawToken.get().size() == 3);
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
            this.signature = Optional.of(copyOf(signature, signature.length));
            return this;
        }

        public DecoderBuilder rawToken(List<String> rawToken) {
            checkNotNull(rawToken);
            checkArgument(rawToken.size() == 3);
            this.rawToken = Optional.of((List<String>) ImmutableList.copyOf(rawToken));
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
            return new JsonWebToken(header, claim, Optional.<byte[]>absent(), Optional.<List<String>>absent());
        }
    }

    public static DecoderBuilder parser() {
        return new DecoderBuilder();
    }

    public static EncoderBuilder builder() {
        return new EncoderBuilder();
    }
}
