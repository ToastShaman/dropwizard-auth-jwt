package com.github.toastshaman.dropwizard.auth.jwt.verifier;

import com.github.toastshaman.dropwizard.auth.jwt.model.JWTToken;
import com.github.toastshaman.dropwizard.auth.jwt.parser.DefaultJWTTokenParser;
import org.junit.Test;

import java.nio.charset.Charset;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

public class HmacSHA256SignatureVerifierTest {

    @Test
    public void
    verifies_a_valid_signature() {

    }
}
