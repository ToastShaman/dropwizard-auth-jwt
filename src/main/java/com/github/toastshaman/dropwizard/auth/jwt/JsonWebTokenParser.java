package com.github.toastshaman.dropwizard.auth.jwt;

import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebToken;

/**
 * Used for classes that are able to transform a string representing a set of
 * claims that have been digitally signed or MACed into a {@code JsonWebToken}.
 *
 * <pre>{@code
 * final String encodedToken = ""
 * + "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9"
 * + ".eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
 * + ".dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
 *
 * JsonWebToken token = new DefaultJsonWebTokenParser().parse(encodedToken);
 * }</pre>
 */
public interface JsonWebTokenParser {

    /**
     * Parses a given bearer token from it's string representation into a {@code JsonWebToken}.
     * @param token the string representation of the bearer token.
     * @return the {@code JsonWebToken} representation of the provided token
     */
    JsonWebToken parse(String token);
}
