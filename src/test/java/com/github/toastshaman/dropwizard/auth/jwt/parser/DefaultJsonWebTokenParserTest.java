package com.github.toastshaman.dropwizard.auth.jwt.parser;

import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebToken;
import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.junit.Test;

import java.beans.Introspector;
import java.beans.MethodDescriptor;
import java.beans.PropertyDescriptor;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;

public class DefaultJsonWebTokenParserTest {

    @Test
    public void
    parses_a_valid_JWT_token() {

        final String encodedToken = ""
                + "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9"
                + ".eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
                + ".dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

        JsonWebToken token = new DefaultJsonWebTokenParser().parse(encodedToken);

        assertThat(token.header(), notNullValue());
        assertThat(token.claim(), notNullValue());

        assertThat(token.header().typ(), equalTo("JWT"));
        assertThat(token.header().alg(), equalTo("HS256"));

        assertThat(token.claim().iss(), equalTo("joe"));
        assertThat(token.claim().exp(), equalTo(1300819380L));
        assertThat((Boolean) token.claim().getParameter("http://example.com/is_root"), equalTo(true));
    }
}
