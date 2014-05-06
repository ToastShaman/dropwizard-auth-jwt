package com.github.toastshaman.dropwizard.auth.jwt.model;

import com.github.toastshaman.dropwizard.auth.jwt.signer.HmacSHA256Signer;
import com.google.common.io.BaseEncoding;
import org.junit.Test;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;


public class JsonWebTokenTest {

    @Test public void
    build_a_valid_token() {

        final String expected = ""
                + "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9"
                + ".eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
                + ".lliDzOlRAdGUCfCHCPx_uisb6ZfZ1LRQa0OJLeYTTpY";

        final byte[] key = decode("AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow");

        JsonWebToken token = JsonWebToken.encode()
                .header(
                        JsonWebTokenHeader.builder().typ("JWT").alg("HS256").build())
                .claim(
                        JsonWebTokenClaims.builder().iss("joe").exp(1300819380).param("http://example.com/is_root", true).build())
                .build();

        HmacSHA256Signer signer = new HmacSHA256Signer(key);

        final String encodedToken = signer.sign(token);

        assertThat(encodedToken, equalTo(expected));
    }

    private byte[] decode(String input) { return BaseEncoding.base64Url().omitPadding().decode(input); }
}
