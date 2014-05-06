package com.github.toastshaman.dropwizard.auth.jwt.parser;

import com.github.toastshaman.dropwizard.auth.jwt.JWTTokenParser;
import com.github.toastshaman.dropwizard.auth.jwt.model.JWTToken;
import org.junit.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasProperty;
import static org.hamcrest.Matchers.notNullValue;

public class DefaultJWTTokenParserTest {

    @Test
    public void
    parses_a_valid_JWT_token() {

        final String encodedToken = ""
                + "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9"
                + ".eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
                + ".dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

        JWTToken token = new DefaultJWTTokenParser().parse(encodedToken);

        assertThat(token.getHeader(), notNullValue());
        assertThat(token.getClaim(), notNullValue());

        assertThat(token.getHeader(), hasProperty("typ", equalTo("JWT")));
        assertThat(token.getHeader(), hasProperty("alg", equalTo("HS256")));

        assertThat(token.getClaim(), hasProperty("iss", equalTo("joe")));
        assertThat(token.getClaim(), hasProperty("exp", equalTo(1300819380)));
        assertThat((Boolean) token.getClaim().getParameter("http://example.com/is_root"), equalTo(true));
    }
}
