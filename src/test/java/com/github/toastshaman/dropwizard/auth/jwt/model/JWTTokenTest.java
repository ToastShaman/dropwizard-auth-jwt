package com.github.toastshaman.dropwizard.auth.jwt.model;

import com.github.toastshaman.dropwizard.auth.jwt.signer.HmacSHA256Signer;
import org.junit.Test;

import java.nio.charset.Charset;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;


public class JWTTokenTest {

    @Test public void
    build_a_valid_token() {

        JWTToken token = JWTToken.encode()
                .header(
                        JWTHeader.builder().typ("JWT").alg("HS256").build())
                .claim(
                        JWTClaim.builder().iss("joe").exp("1300819380").param("http://example.com/is_root", true).build()).build();

        HmacSHA256Signer signer = new HmacSHA256Signer("SECRET".getBytes(Charset.forName("UTF-8")));

        final String encodedToken = signer.sign(token);

        assertThat(encodedToken, equalTo("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLCJleHAiOiIxMzAwODE5MzgwIiwiaHR0cDovL2V4YW1wbGUuY29tL2lzX3Jvb3QiOnRydWV9.FNaQO-fkPiEmGj8DVhNnozy35hT-8elA-NvoQsmW41M"));
    }
}
