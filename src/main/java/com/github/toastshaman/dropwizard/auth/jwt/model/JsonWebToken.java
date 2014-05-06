package com.github.toastshaman.dropwizard.auth.jwt.model;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.toastshaman.dropwizard.auth.jwt.exceptioons.JsonWebTokenException;
import com.github.toastshaman.dropwizard.auth.jwt.exceptioons.MalformedJsonWebTokenException;
import com.google.common.base.Joiner;
import com.google.common.base.Optional;
import com.google.common.collect.ImmutableList;
import com.google.common.io.BaseEncoding;

import java.io.IOException;
import java.io.StringWriter;
import java.nio.charset.Charset;
import java.util.List;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;
import static java.lang.String.format;
import static java.util.Arrays.copyOf;
import static org.apache.commons.lang.StringUtils.isNotBlank;

public class JsonWebToken {

    private final JWTHeader header;

    private final JWTClaim claim;

    private Optional<byte[]> signature;

    private Optional<List<String>> rawToken = Optional.absent();

    private JsonWebToken(JWTHeader header, JWTClaim claim, Optional<byte[]> signature, Optional<List<String>> rawToken) {
        this.header = header;
        this.claim = claim;
        this.signature = signature;
        this.rawToken = rawToken;
    }

    public JWTHeader getHeader() { return header; }

    public JWTClaim getClaim() { return claim; }

    public byte[] getSignature() { return signature.orNull(); }

    public String deserialize() { return Joiner.on(".").join(encode(toJson(header)), encode(toJson(claim))); }

    private String encode(String input) {
        return BaseEncoding.base64Url().omitPadding().encode(input.getBytes(Charset.forName("UTF-8")));
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

    public Optional<List<String>> getRawToken() { return rawToken; }

    public static class DecoderBuilder {

        private ObjectMapper mapper = new ObjectMapper();

        private JWTHeader header;

        private JWTClaim claim;

        private Optional<byte[]> signature = Optional.absent();

        private Optional<List<String>> rawToken = Optional.absent();

        public JsonWebToken build() {
            checkNotNull(header);
            checkNotNull(claim);
            checkNotNull(rawToken);
            if (signature.isPresent()) { checkArgument(signature.get().length > 0); }
            if (rawToken.isPresent()) { checkArgument(rawToken.get().size() == 3); };
            return new JsonWebToken(header, claim, signature, rawToken);
        }

        public DecoderBuilder header(String header) {
            checkArgument(isNotBlank(header));
            try {
                this.header = mapper.readValue(header, JWTHeader.class);
                return this;
            } catch (Exception e) {
                throw new MalformedJsonWebTokenException(format("The provided JWT header is malformed: [%s]", header), e);
            }
        }

        public DecoderBuilder claim(String claim) {
            checkArgument(isNotBlank(claim));
            try {
                this.claim = mapper.readValue(claim, JWTClaim.class);
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

        private JWTHeader header;

        private JWTClaim claim;

        public EncoderBuilder header(JWTHeader header) {
            checkNotNull(header);
            this.header = header;
            return this;
        }

        public EncoderBuilder claim(JWTClaim claim) {
            checkNotNull(claim);
            this.claim = claim;
            return this;
        }

        public JsonWebToken build() {
            checkNotNull(claim);
            checkNotNull(header);
            return new JsonWebToken(header, claim, Optional.<byte[]>absent(), Optional.<List<String>>absent());
        }
    }

    public static DecoderBuilder decode() { return new DecoderBuilder(); }

    public static EncoderBuilder encode() { return new EncoderBuilder(); }
}
