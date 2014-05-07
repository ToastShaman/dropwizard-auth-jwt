package com.github.toastshaman.dropwizard.auth.jwt.model;

import com.github.toastshaman.dropwizard.auth.jwt.hmac.HmacSHA256Signer;
import org.joda.time.DateTime;
import org.joda.time.Instant;
import org.junit.Test;

import static com.github.toastshaman.dropwizard.auth.jwt.JsonWebTokenUtils.fromBase64;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;

public class JsonWebTokenTest {

    @Test public void
    build_a_valid_token() {

        final String expected = ""
                + "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9"
                + ".eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
                + ".lliDzOlRAdGUCfCHCPx_uisb6ZfZ1LRQa0OJLeYTTpY";

        final byte[] key = fromBase64("AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow");

        JsonWebToken token = JsonWebToken.encode()
                .header(JsonWebTokenHeader.HS256())
                .claim(
                        JsonWebTokenClaims.builder()
                                .iss("joe")
                                .exp(DateTime.now().withMillis(1300819380000L))
                                .param("http://example.com/is_root", true)
                                .build()
                )
                .build();

        final String encodedToken = new HmacSHA256Signer(key).sign(token);

        assertThat(encodedToken, equalTo(expected));
    }
}
