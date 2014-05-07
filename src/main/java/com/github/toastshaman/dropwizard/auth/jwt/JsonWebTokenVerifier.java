package com.github.toastshaman.dropwizard.auth.jwt;

import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebToken;

public interface JsonWebTokenVerifier {

    String algorithm();

    void verifySignature(JsonWebToken token);

}
