package com.github.toastshaman.dropwizard.auth.jwt;

import com.github.toastshaman.dropwizard.auth.jwt.model.JWTToken;

public interface JWTTokenSigner {

    String algorithm();

    String sign(JWTToken token);
}
