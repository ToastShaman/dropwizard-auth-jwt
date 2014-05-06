package com.github.toastshaman.dropwizard.auth.jwt.model;

import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.common.collect.ImmutableBiMap;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Maps;
import org.hibernate.validator.constraints.NotEmpty;

import java.util.Map;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.Maps.newHashMap;
import static org.apache.commons.lang.StringUtils.isNotBlank;

public class JWTClaim {

    @JsonProperty("iss")
    private String iss;

    @JsonProperty("exp")
    private String exp;

    private Map<String, Object> params = newHashMap();

    private JWTClaim() {
        // we need an empty constructor for the Jackson mapper
    }

    private JWTClaim(String iss, String exp, Map<String, Object> params) {
        this.iss = iss;
        this.exp = exp;
        this.params = ImmutableMap.copyOf(params);
    }

    public String getExp() { return exp; }

    public String getIss() { return iss; }

    @JsonAnySetter
    private void addParameter(String key, Object object) { this.params.put(key, object); }

    @JsonAnyGetter
    private Map<String, Object> getParameters() { return params; }

    public Object getParameter(String key) { return params.get(key); }

    public static class Builder {

        private String iss;

        private String exp;

        private Map<String, Object> params = newHashMap();

        public JWTClaim build() {
            return new JWTClaim(iss, exp, params);
        }

        public Builder iss(String iss) {
            checkArgument(isNotBlank(iss));

            this.iss = iss;
            return this;
        }

        public Builder exp(String exp) {
            checkArgument(isNotBlank(exp));

            this.exp = exp;
            return this;
        }

        public Builder param(String key, Object value) {
            checkArgument(isNotBlank(key));
            checkNotNull(value);

            params.put(key, value);
            return this;
        }
    }

    public static Builder builder() { return new Builder(); }
}
