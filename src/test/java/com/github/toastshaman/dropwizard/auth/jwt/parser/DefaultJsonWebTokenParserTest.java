package com.github.toastshaman.dropwizard.auth.jwt.parser;

import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebToken;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class DefaultJsonWebTokenParserTest {

    @Test
    public void
    parses_a_valid_JWT_token() {

        final String encodedToken = ""
                + "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9"
                + ".eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
                + ".dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

        JsonWebToken token = new DefaultJsonWebTokenParser().parse(encodedToken);

        assertThat(token.header()).isNotNull();
        assertThat(token.claim()).isNotNull();

        assertThat(token.header().type()).isEqualTo("JWT");
        assertThat(token.header().algorithm()).isEqualTo("HS256");

        assertThat(token.claim().issuer()).isEqualTo("joe");
        assertThat(token.claim().expiration()).isEqualTo(1300819380L);
        assertThat((Boolean) token.claim().getParameter("http://example.com/is_root")).isEqualTo(true);
    }
}
