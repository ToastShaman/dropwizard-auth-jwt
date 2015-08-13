package com.github.toastshaman.dropwizard.auth.jwt;

import com.github.toastshaman.dropwizard.auth.jwt.hmac.HmacSHA512Signer;
import com.github.toastshaman.dropwizard.auth.jwt.hmac.HmacSHA512Verifier;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebToken;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebTokenClaim;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebTokenHeader;
import com.github.toastshaman.dropwizard.auth.jwt.parser.DefaultJsonWebTokenParser;
import com.google.common.collect.ImmutableList;
import io.dropwizard.jersey.DropwizardResourceConfig;
import org.joda.time.DateTime;
import org.junit.Test;

import javax.ws.rs.WebApplicationException;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.core.HttpHeaders;

import static com.github.toastshaman.dropwizard.auth.jwt.JsonWebTokenUtils.bytesOf;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.failBecauseExceptionWasNotThrown;

public class JWTAuthProviderTest extends AuthBaseTest<JWTAuthProviderTest.JWTAuthTestResourceConfig> {

    private static final byte[] SECRET_KEY = bytesOf("MySecretKey");

    public static class JWTAuthTestResourceConfig extends AuthBaseResourceConfig {
        protected ContainerRequestFilter getAuthFilter() {
            return new JWTAuthFilter.Builder<>()
                    .setTokenParser(new DefaultJsonWebTokenParser())
                    .setTokenVerifier(new HmacSHA512Verifier(SECRET_KEY))
                    .setPrefix(BEARER_PREFIX)
                    .setAuthorizer(AuthUtil.getTestAuthorizer(ADMIN_USER, ADMIN_ROLE))
                    .setAuthenticator(AuthUtil.getJWTAuthenticator(ImmutableList.of(ADMIN_USER, ORDINARY_USER)))
                    .buildAuthFilter();
        }
    }

    @Test
    public void respondsToInvalidSignaturesWith401() throws Exception {
        try {
            target("/test/admin").request()
                    .header(HttpHeaders.AUTHORIZATION, getPrefix() + " " + getInvalidToken())
                    .get(String.class);
            failBecauseExceptionWasNotThrown(WebApplicationException.class);
        } catch (WebApplicationException e) {
            assertThat(e.getResponse().getStatus()).isEqualTo(401);
            assertThat(e.getResponse().getHeaders().get(HttpHeaders.WWW_AUTHENTICATE))
                    .containsOnly(getPrefix() + " realm=\"realm\"");
        }
    }

    @Test
    public void respondsToExpiredTokensWith401() throws Exception {
        try {
            target("/test/admin").request()
                    .header(HttpHeaders.AUTHORIZATION, getPrefix() + " " + getOrdinaryGuyExpiredToken())
                    .get(String.class);
            failBecauseExceptionWasNotThrown(WebApplicationException.class);
        } catch (WebApplicationException e) {
            assertThat(e.getResponse().getStatus()).isEqualTo(401);
            assertThat(e.getResponse().getHeaders().get(HttpHeaders.WWW_AUTHENTICATE))
                    .containsOnly(getPrefix() + " realm=\"realm\"");
        }
    }

    @Override
    protected DropwizardResourceConfig getDropwizardResourceConfig() {
        return new JWTAuthTestResourceConfig();
    }

    @Override
    protected Class<JWTAuthTestResourceConfig> getDropwizardResourceConfigClass() {
        return JWTAuthTestResourceConfig.class;
    }

    @Override
    protected String getPrefix() {
        return BEARER_PREFIX;
    }

    @Override
    protected String getOrdinaryGuyValidToken() {
        final JsonWebToken token = JsonWebToken.builder()
                .header(JsonWebTokenHeader.HS512())
                .claim(JsonWebTokenClaim.builder().subject(ORDINARY_USER).build())
                .build();
        return new HmacSHA512Signer(SECRET_KEY).sign(token);
    }

    protected String getOrdinaryGuyExpiredToken() {
        final JsonWebToken token = JsonWebToken.builder()
                .header(JsonWebTokenHeader.HS512())
                .claim(JsonWebTokenClaim.builder()
                        .expiration(DateTime.now().minusDays(1))
                        .subject(ORDINARY_USER)
                        .build())
                .build();
        return new HmacSHA512Signer(SECRET_KEY).sign(token);
    }

    @Override
    protected String getGoodGuyValidToken() {
        final JsonWebToken token = JsonWebToken.builder()
                .header(JsonWebTokenHeader.HS512())
                .claim(JsonWebTokenClaim.builder().subject(ADMIN_USER).build())
                .build();
        return new HmacSHA512Signer(SECRET_KEY).sign(token);
    }

    @Override
    protected String getBadGuyToken() {
        final JsonWebToken token = JsonWebToken.builder()
                .header(JsonWebTokenHeader.HS512())
                .claim(JsonWebTokenClaim.builder().subject(BADGUY_USER).build())
                .build();
        return new HmacSHA512Signer(SECRET_KEY).sign(token);
    }

    protected String getInvalidToken() {
        final JsonWebToken token = JsonWebToken.builder()
                .header(JsonWebTokenHeader.HS512())
                .claim(JsonWebTokenClaim.builder().subject(BADGUY_USER).build())
                .build();
        return new HmacSHA512Signer(bytesOf("DERP")).sign(token);
    }
}
