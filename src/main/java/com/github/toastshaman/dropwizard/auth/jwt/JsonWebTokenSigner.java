package com.github.toastshaman.dropwizard.auth.jwt;

import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebToken;

public interface JsonWebTokenSigner {

    String algorithm();

    String sign(JsonWebToken token);
}
