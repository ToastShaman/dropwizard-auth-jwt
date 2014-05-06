package com.github.toastshaman.dropwizard.auth.jwt.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.common.base.Preconditions;
import com.google.common.collect.Maps;
import org.apache.commons.lang.StringUtils;
import org.hibernate.validator.constraints.NotEmpty;

import java.util.Map;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.Maps.newHashMap;
import static org.apache.commons.lang.StringUtils.isNotBlank;

public class JWTHeader {

    @JsonProperty("typ")
    @NotEmpty
    private String typ;

    @JsonProperty("alg")
    @NotEmpty
    private String alg;

    private JWTHeader() {
        // we need an empty constructor for the Jackson mapper
    }

    private JWTHeader(String typ, String alg) {
        this.typ = typ;
        this.alg = alg;
    }

    public String getAlg() { return alg; }

    public String getTyp() { return typ; }

    public static class Builder {

        private String typ;

        private String alg;

        private Map<String, Object> params = newHashMap();

        public JWTHeader build() {
            checkArgument(isNotBlank(alg));
            checkArgument(isNotBlank(typ));
            return new JWTHeader(typ, alg);
        }

        public Builder alg(String alg) {
            checkArgument(isNotBlank(alg));
            this.alg = alg;
            return this;
        }

        public Builder typ(String typ) {
            checkArgument(isNotBlank(typ));
            this.typ = typ;
            return this;
        }
    }

    public static Builder builder() { return new Builder(); }
}
