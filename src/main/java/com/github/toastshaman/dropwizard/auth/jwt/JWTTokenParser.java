package com.github.toastshaman.dropwizard.auth.jwt;

import com.github.toastshaman.dropwizard.auth.jwt.model.JWTToken;

public interface JWTTokenParser {

    JWTToken parse(String token);
}
