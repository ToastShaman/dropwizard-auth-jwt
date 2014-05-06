package com.github.toastshaman.dropwizard.auth.jwt;

public class JWTTokenParser {

    private final String secret;

    public JWTTokenParser(String secret) {
        this.secret = secret;
    }

    public JWTToken parse(String token) {
        return new JWTToken();
    }
}
