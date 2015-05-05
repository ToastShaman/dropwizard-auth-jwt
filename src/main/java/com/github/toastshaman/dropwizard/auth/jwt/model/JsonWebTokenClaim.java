package com.github.toastshaman.dropwizard.auth.jwt.model;

import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.google.common.collect.ImmutableMap;
import org.joda.time.DateTime;

import java.util.Map;

import static com.fasterxml.jackson.databind.annotation.JsonSerialize.Inclusion.NON_NULL;
import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.Maps.newHashMap;
import static org.apache.commons.lang3.StringUtils.isNotBlank;

/**
 * A JSON representation of a JWT claim.
 *
 * <pre>{@code
 * final JsonWebToken token = JsonWebToken.builder()
 *     .header(JsonWebTokenHeader.HS512())
 *     .claim(JsonWebTokenClaim.builder().subject("joe").build())
 *     .build();
 * }</pre>
 */
@JsonSerialize(include = NON_NULL)
public class JsonWebTokenClaim {

    @JsonProperty("iss")
    private String iss;

    @JsonProperty("exp")
    private Long exp;

    @JsonProperty("iat")
    private Long iat;

    @JsonProperty("nbf")
    private Long nbf;

    @JsonProperty("sub")
    private String sub;

    private Map<String, Object> params = newHashMap();

    private JsonWebTokenClaim() {
        // we need an empty constructor for the Jackson mapper
    }

    private JsonWebTokenClaim(
            String sub,
            String iss,
            Long iat,
            Long exp,
            Long nbf,
            Map<String, Object> params) {
        this.sub = sub;
        this.iss = iss;
        this.exp = exp;
        this.iat = iat;
        this.nbf = nbf;
        this.params = ImmutableMap.copyOf(params);
    }

    /**
     * The exp (expiration time) claim identifies the expiration time on or after which the token MUST NOT
     * be accepted for processing. The processing of the exp claim requires that the current date/time
     * MUST be before the expiration date/time listed in the exp claim. Implementers MAY provide for
     * some small leeway, usually no more than a few minutes, to account for clock skew.
     * Use of this claim is OPTIONAL.
     * @return the expiration time
     */
    public Long expiration() {
        return exp;
    }

    /**
     * The iss (issuer) claim identifies the principal that issued the token. The processing of this claim is
     * generally application specific. The iss value is a case-sensitive string containing a String Oor URI value.
     * Use of this claim is OPTIONAL.
     * @return the issuer
     */
    public String issuer() {
        return iss;
    }

    /**
     * The iat (issued at) claim identifies the time at which the token was issued. This claim can be used to
     * determine the age of the token. Use of this claim is OPTIONAL.
     * @return the issued at time
     */
    public Long issuedAt() {
        return iat;
    }

    /**
     * The nbf (not before) claim identifies the time before which the token MUST NOT be accepted for processing.
     * The processing of the notBefore claim requires that the current date/time MUST be after or equal to
     * the not-before date/time listed in the notBefore claim. Implementers MAY provide for some small leeway,
     * usually no more than a few minutes, to account for clock skew. Use of this claim is OPTIONAL.
     * @return the not before time
     */
    public Long notBefore() {
        return nbf;
    }

    /**
     * The sub (subject) claim identifies the principal that is the subject of the token.
     * The Claims in a token are normally statements about the subject. The subject value MUST
     * either be scoped to be locally unique in the context of the issuer or be globally unique.
     * The processing of this claim is generally application specific. The sub value is a case-sensitive
     * string containing a StringOrURI value. Use of this claim is OPTIONAL.
     * @return the subject
     */
    public String subject() {
        return sub;
    }

    @JsonAnySetter
    private void addParameter(String key, Object object) {
        this.params.put(key, object);
    }

    @JsonAnyGetter
    private Map<String, Object> getParameters() {
        return params;
    }

    public Object getParameter(String key) {
        return params.get(key);
    }

    public static class Builder {

        private String sub;

        private String iss;

        private Long exp;

        private Long iat;

        private Long nbf;

        private Map<String, Object> params = newHashMap();

        public JsonWebTokenClaim build() {
            return new JsonWebTokenClaim(sub, iss, iat, exp, nbf, params);
        }

        /**
         * The sub (subject) claim identifies the principal that is the subject of the token.
         * The Claims in a token are normally statements about the subject. The subject value MUST
         * either be scoped to be locally unique in the context of the issuer or be globally unique.
         * The processing of this claim is generally application specific. The sub value is a case-sensitive
         * string containing a StringOrURI value. Use of this claim is OPTIONAL.
         * @param sub the subject
         */
        public Builder subject(String sub) {
            checkNotNull(sub);
            checkArgument(isNotBlank(sub));
            this.sub = sub;
            return this;
        }

        /**
         * The iss (issuer) claim identifies the principal that issued the token. The processing of this claim is
         * generally application specific. The iss value is a case-sensitive string containing a String Oor URI value.
         * Use of this claim is OPTIONAL.
         * @param iss the issuer
         */
        public Builder issuer(String iss) {
            checkNotNull(iss);
            checkArgument(isNotBlank(iss));
            this.iss = iss;
            return this;
        }

        /**
         * The exp (expiration time) claim identifies the expiration time on or after which the token MUST NOT
         * be accepted for processing. The processing of the exp claim requires that the current date/time
         * MUST be before the expiration date/time listed in the exp claim. Implementers MAY provide for
         * some small leeway, usually no more than a few minutes, to account for clock skew.
         * Use of this claim is OPTIONAL.
         * @param time the expiration time
         */
        public Builder expiration(DateTime time) {
            checkNotNull(time);
            this.exp = time.getMillis() / 1000;
            return this;
        }

        /**
         * The iat (issued at) claim identifies the time at which the token was issued. This claim can be used to
         * determine the age of the token. Use of this claim is OPTIONAL.
         * @param time the issued at time
         */
        public Builder issuedAt(DateTime time) {
            checkNotNull(time);
            this.iat = time.getMillis() / 1000;
            return this;
        }

        /**
         * The nbf (not before) claim identifies the time before which the token MUST NOT be accepted for processing.
         * The processing of the notBefore claim requires that the current date/time MUST be after or equal to
         * the not-before date/time listed in the notBefore claim. Implementers MAY provide for some small leeway,
         * usually no more than a few minutes, to account for clock skew. Use of this claim is OPTIONAL.
         * @param time the not before time
         */
        public Builder notBefore(DateTime time) {
            checkNotNull(time);
            this.nbf = time.getMillis() / 1000;
            return this;
        }

        /**
         * Adds other key/value pairs to the claim.
         * @param key the name of the claim you want to add
         * @param value the value of the claim you want to add
         */
        public Builder param(String key, Object value) {
            checkNotNull(key);
            checkNotNull(value);
            checkArgument(isNotBlank(key));
            params.put(key, value);
            return this;
        }
    }

    public static Builder builder() {
        return new Builder();
    }
}
