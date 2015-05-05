package com.github.toastshaman.dropwizard.auth.jwt.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import org.hibernate.validator.constraints.NotEmpty;

import java.util.Map;

import static com.fasterxml.jackson.databind.annotation.JsonSerialize.Inclusion.NON_NULL;
import static com.github.toastshaman.dropwizard.auth.jwt.JsonWebTokenAlgorithms.*;
import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.Maps.newHashMap;
import static org.apache.commons.lang3.StringUtils.isNotBlank;

/**
 * JSON representation of the token header.
 */
@JsonSerialize(include = NON_NULL)
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

    /**
     * The algorithm used to sign the token.
     * @return the algorithm
     */
    public String algorithm() {
        return alg;
    }

    /**
     * The typ (type) Header Parameter defined by [JWS] and [JWE] is used by JWT applications to declare
     * the MIME Media Type [IANA.MediaTypes] of this complete token. This is intended for use by the JWT
     * application when values that are not JWTs could also be present in an application data structure that
     * can contain a JWT object; the application can use this value to disambiguate among the different
     * kinds of objects that might be present. It will typically not be used by applications when it
     * is already known that the object is a JWT. This parameter is ignored by JWT implementations;
     * any processing of this parameter is performed by the JWT application. If present,
     * it is RECOMMENDED that its value be JWT to indicate that this object is a JWT. While media
     * type names are not case-sensitive, it is RECOMMENDED that JWT always be spelled using uppercase characters
     * for compatibility with legacy implementations. Use of this Header Parameter is OPTIONAL.
     * @return the type
     */
    public String type() {
        return typ;
    }

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

        /**
         * The algorithm used to sign the token.
         * @param alg the algorithm
         */
        public Builder algorithm(String alg) {
            checkNotNull(alg);
            checkArgument(isNotBlank(alg));
            this.alg = alg.toUpperCase();
            return this;
        }

        /**
         * The typ (type) Header Parameter defined by [JWS] and [JWE] is used by JWT applications to declare
         * the MIME Media Type [IANA.MediaTypes] of this complete token. This is intended for use by the JWT
         * application when values that are not JWTs could also be present in an application data structure that
         * can contain a JWT object; the application can use this value to disambiguate among the different
         * kinds of objects that might be present. It will typically not be used by applications when it
         * is already known that the object is a JWT. This parameter is ignored by JWT implementations;
         * any processing of this parameter is performed by the JWT application. If present,
         * it is RECOMMENDED that its value be JWT to indicate that this object is a JWT. While media
         * type names are not case-sensitive, it is RECOMMENDED that JWT always be spelled using uppercase characters
         * for compatibility with legacy implementations. Use of this Header Parameter is OPTIONAL.
         * @param typ the type
         */
        public Builder type(String typ) {
            checkNotNull(typ);
            checkArgument(isNotBlank(typ));
            this.typ = typ.toUpperCase();
            return this;
        }
    }

    public static Builder builder() {
        return new Builder();
    }

    public static JsonWebTokenHeader HS256() {
        return new JsonWebTokenHeader(JWT_HEADER, HS256);
    }

    public static JsonWebTokenHeader HS384() {
        return new JsonWebTokenHeader(JWT_HEADER, HS384);
    }

    public static JsonWebTokenHeader HS512() {
        return new JsonWebTokenHeader(JWT_HEADER, HS512);
    }
}
