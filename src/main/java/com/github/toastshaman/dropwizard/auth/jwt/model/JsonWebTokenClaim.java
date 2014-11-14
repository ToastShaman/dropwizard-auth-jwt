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
import static org.apache.commons.lang.StringUtils.isNotBlank;

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

    private Map<String, Object> params = newHashMap();

    private JsonWebTokenClaim() {
        // we need an empty constructor for the Jackson mapper
    }

    private JsonWebTokenClaim(
            String iss,
            Long iat,
            Long exp,
            Long nbf,
            Map<String, Object> params) {
        this.iss = iss;
        this.exp = exp;
        this.iat = iat;
        this.nbf = nbf;
        this.params = ImmutableMap.copyOf(params);
    }

    public Long expiration() {
        return exp;
    }

    public String issuer() {
        return iss;
    }

    public Long issuedAt() {
        return iat;
    }

    public Long notBefore() {
        return nbf;
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

        private String iss;

        private Long exp;

        private Long iat;

        private Long nbf;

        private Map<String, Object> params = newHashMap();

        public JsonWebTokenClaim build() {
            return new JsonWebTokenClaim(iss, iat, exp, nbf, params);
        }

        public Builder issuer(String iss) {
            checkNotNull(iss);
            checkArgument(isNotBlank(iss));
            this.iss = iss;
            return this;
        }

        public Builder expiration(DateTime time) {
            checkNotNull(time);
            this.exp = time.getMillis() / 1000;
            return this;
        }

        public Builder issuedAt(DateTime time) {
            checkNotNull(time);
            this.iat = time.getMillis() / 1000;
            return this;
        }

        public Builder notBefore(DateTime time) {
            checkNotNull(time);
            this.nbf = time.getMillis() / 1000;
            return this;
        }

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
