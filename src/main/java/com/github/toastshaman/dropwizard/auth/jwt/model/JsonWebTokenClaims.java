package com.github.toastshaman.dropwizard.auth.jwt.model;

import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.common.collect.ImmutableMap;
import org.joda.time.DateTime;
import org.joda.time.Instant;

import java.util.Map;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.Maps.newHashMap;
import static org.apache.commons.lang.StringUtils.isNotBlank;

public class JsonWebTokenClaims {

    @JsonProperty("iss")
    private String iss;

    @JsonProperty("exp")
    private Long exp;

    private Map<String, Object> params = newHashMap();

    private JsonWebTokenClaims() {
        // we need an empty constructor for the Jackson mapper
    }

    private JsonWebTokenClaims(String iss, Long exp, Map<String, Object> params) {
        this.iss = iss;
        this.exp = exp;
        this.params = ImmutableMap.copyOf(params);
    }

    public Long exp() { return exp; }

    public String iss() { return iss; }

    @JsonAnySetter
    private void addParameter(String key, Object object) { this.params.put(key, object); }

    @JsonAnyGetter
    private Map<String, Object> getParameters() { return params; }

    public Object getParameter(String key) { return params.get(key); }

    public static class Builder {

        private String iss;

        private Long exp;

        private Map<String, Object> params = newHashMap();

        public JsonWebTokenClaims build() { return new JsonWebTokenClaims(iss, exp, params); }

        public Builder iss(String iss) {
            checkNotNull(iss);
            checkArgument(isNotBlank(iss));
            this.iss = iss;
            return this;
        }

        public Builder exp(DateTime time) {
            checkNotNull(time);
            this.exp = time.getMillis() / 1000;
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

    public static Builder builder() { return new Builder(); }
}
