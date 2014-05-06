package com.github.toastshaman.dropwizard.auth.jwt;

import com.github.toastshaman.dropwizard.auth.jwt.model.JWTToken;

public interface JWTTokenVerifier {

    String algorithm();

    boolean verifySignature(JWTToken token, byte[] signature);

}
