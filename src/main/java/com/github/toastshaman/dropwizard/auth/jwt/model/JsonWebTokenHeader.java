package com.github.toastshaman.dropwizard.auth.jwt.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.hibernate.validator.constraints.NotEmpty;

import java.util.Map;

import static com.github.toastshaman.dropwizard.auth.jwt.JsonWebTokenAlgorithms.*;
import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.Maps.newHashMap;
import static org.apache.commons.lang.StringUtils.isNotBlank;

public class JsonWebTokenHeader {

    private static final String JWT_HEADER = "JWT";

    @JsonProperty("typ")
    @NotEmpty
    private String typ;

    @JsonProperty("alg")
    @NotEmpty
    private String alg;

    private JsonWebTokenHeader() {
        // we need an empty constructor for the Jackson mapper
    }

    private JsonWebTokenHeader(String typ, String alg) {
        this.typ = typ;
        this.alg = alg;
    }

    public String alg() { return alg; }

    public String typ() { return typ; }

    public static class Builder {

        private String typ;

        private String alg;

        private Map<String, Object> params = newHashMap();

        public JsonWebTokenHeader build() {
            checkNotNull(alg);
            checkNotNull(typ);
            checkArgument(isNotBlank(alg));
            checkArgument(isNotBlank(typ));
            return new JsonWebTokenHeader(typ, alg);
        }

        public Builder alg(String alg) {
            checkNotNull(alg);
            checkArgument(isNotBlank(alg));
            this.alg = alg.toUpperCase();
            return this;
        }

        public Builder typ(String typ) {
            checkNotNull(typ);
            checkArgument(isNotBlank(typ));
            this.typ = typ.toUpperCase();
            return this;
        }
    }

    public static Builder builder() { return new Builder(); }

    public static JsonWebTokenHeader HS256() { return new JsonWebTokenHeader(JWT_HEADER, HS256); }

    public static JsonWebTokenHeader HS384() { return new JsonWebTokenHeader(JWT_HEADER, HS384); }

    public static JsonWebTokenHeader HS512() { return new JsonWebTokenHeader(JWT_HEADER, HS512); }
}
