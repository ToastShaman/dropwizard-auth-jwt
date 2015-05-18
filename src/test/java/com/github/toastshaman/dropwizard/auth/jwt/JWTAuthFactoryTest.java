package com.github.toastshaman.dropwizard.auth.jwt;

import com.codahale.metrics.MetricRegistry;
import com.github.toastshaman.dropwizard.auth.jwt.hmac.HmacSHA512Signer;
import com.github.toastshaman.dropwizard.auth.jwt.hmac.HmacSHA512Verifier;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebToken;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebTokenClaim;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebTokenHeader;
import com.github.toastshaman.dropwizard.auth.jwt.parser.DefaultJsonWebTokenParser;
import com.github.toastshaman.dropwizard.auth.jwt.validator.ExpiryValidator;
import com.google.common.base.Optional;
import io.dropwizard.auth.AuthFactory;
import io.dropwizard.auth.AuthenticationException;
import io.dropwizard.auth.Authenticator;
import io.dropwizard.jersey.DropwizardResourceConfig;
import io.dropwizard.logging.LoggingFactory;
import org.glassfish.jersey.servlet.ServletProperties;
import org.glassfish.jersey.test.DeploymentContext;
import org.glassfish.jersey.test.JerseyTest;
import org.glassfish.jersey.test.ServletDeploymentContext;
import org.glassfish.jersey.test.grizzly.GrizzlyWebTestContainerFactory;
import org.glassfish.jersey.test.spi.TestContainerException;
import org.glassfish.jersey.test.spi.TestContainerFactory;
import org.joda.time.DateTime;
import org.junit.Test;

import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.HttpHeaders;

import static com.github.toastshaman.dropwizard.auth.jwt.JsonWebTokenUtils.bytesOf;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.failBecauseExceptionWasNotThrown;

public class JWTAuthFactoryTest extends JerseyTest {

    static {
        LoggingFactory.bootstrap();
    }

    @Override
    protected TestContainerFactory getTestContainerFactory()
            throws TestContainerException {
        return new GrizzlyWebTestContainerFactory();
    }

    @Override
    protected DeploymentContext configureDeployment() {
        return ServletDeploymentContext.builder(new JwtAuthTestResourceConfig())
                .initParam(ServletProperties.JAXRS_APPLICATION_CLASS, JwtAuthTestResourceConfig.class.getName())
                .build();
    }

    @Test
    public void respondsToMissingCredentialsWith401() throws Exception {
        try {
            target("/test").request().get(String.class);
            failBecauseExceptionWasNotThrown(WebApplicationException.class);
        } catch (WebApplicationException e) {
            assertThat(e.getResponse().getStatus()).isEqualTo(401);
            assertThat(e.getResponse().getHeaders().get(HttpHeaders.WWW_AUTHENTICATE))
                    .containsOnly("Bearer realm=\"realm\"");
        }
    }

    @Test
    public void transformsCredentialsToPrincipals() throws Exception {
        final byte[] TOKEN_SECRET_KEY = bytesOf("MySecretKey");
        final HmacSHA512Signer signer = new HmacSHA512Signer(TOKEN_SECRET_KEY);
        final JsonWebToken token = JsonWebToken.builder()
                .header(JsonWebTokenHeader.HS512())
                .claim(JsonWebTokenClaim.builder().param("principal", "good-guy").build())
                .build();
        final String signedToken = signer.sign(token);

        assertThat(target("/test").request()
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + signedToken)
                .get(String.class)).isEqualTo("good-guy");
    }

    @Test
    public void respondsToNonBasicCredentialsWith401() throws Exception {
        try {
            target("/test").request()
                    .header(HttpHeaders.AUTHORIZATION, "Derp WHEE")
                    .get(String.class);
            failBecauseExceptionWasNotThrown(WebApplicationException.class);
        } catch (WebApplicationException e) {
            assertThat(e.getResponse().getStatus()).isEqualTo(401);
            assertThat(e.getResponse().getHeaders().get(HttpHeaders.WWW_AUTHENTICATE))
                    .containsOnly("Bearer realm=\"realm\"");
        }
    }

    @Test
    public void respondsToInvalidSignaturesWith401() throws Exception {
        try {
            final byte[] TOKEN_SECRET_KEY = bytesOf("DIFFERENT_KEY");
            final HmacSHA512Signer signer = new HmacSHA512Signer(TOKEN_SECRET_KEY);
            final JsonWebToken token = JsonWebToken.builder().header(JsonWebTokenHeader.HS512())
                    .claim(JsonWebTokenClaim.builder().param("principal", "good-guy").build())
                    .build();
            final String signedToken = signer.sign(token);

            target("/test").request()
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + signedToken)
                    .get(String.class);

            failBecauseExceptionWasNotThrown(WebApplicationException.class);
        } catch (WebApplicationException e) {
            assertThat(e.getResponse().getStatus()).isEqualTo(401);
        }
    }

    @Test
    public void respondsToExpiredTokensWith401() throws Exception {
        try {
            final byte[] TOKEN_SECRET_KEY = bytesOf("MySecretKey");
            final HmacSHA512Signer signer = new HmacSHA512Signer(TOKEN_SECRET_KEY);
            final JsonWebToken token = JsonWebToken.builder()
                    .header(JsonWebTokenHeader.HS512())
                    .claim(JsonWebTokenClaim.builder()
                            .expiration(DateTime.now().minusDays(1))
                            .param("principal", "good-guy").build())
                    .build();
            final String signedToken = signer.sign(token);

            target("/test").request()
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + signedToken)
                    .get(String.class);
            failBecauseExceptionWasNotThrown(WebApplicationException.class);
        } catch (WebApplicationException e) {
            assertThat(e.getResponse().getStatus()).isEqualTo(401);
        }
    }

    @Test
    public void respondsToExceptionsWith500() throws Exception {
        try {
            final byte[] TOKEN_SECRET_KEY = bytesOf("MySecretKey");
            final HmacSHA512Signer signer = new HmacSHA512Signer(TOKEN_SECRET_KEY);
            final JsonWebToken token = JsonWebToken.builder().header(JsonWebTokenHeader.HS512())
                    .claim(JsonWebTokenClaim.builder().param("principal", "bad-guy").build())
                    .build();
            final String signedToken = signer.sign(token);

            target("/test").request()
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + signedToken)
                    .get(String.class);
            failBecauseExceptionWasNotThrown(WebApplicationException.class);
        } catch (WebApplicationException e) {
            assertThat(e.getResponse().getStatus()).isEqualTo(500);
        }
    }

    public static class JwtAuthTestResourceConfig extends DropwizardResourceConfig {
        public JwtAuthTestResourceConfig() {
            super(true, new MetricRegistry());

            final Authenticator<JsonWebToken, String> authenticator = new Authenticator<JsonWebToken, String>() {
                @Override
                public Optional<String> authenticate(JsonWebToken credentials) throws AuthenticationException {

                    final ExpiryValidator validator = new ExpiryValidator();
                    validator.validate(credentials);

                    if ("good-guy".equals(credentials.claim().getParameter("principal"))) {
                        return Optional.of("good-guy");
                    }
                    if ("bad-guy".equals(credentials.claim().getParameter("principal"))) {
                        throw new AuthenticationException("CRAP");
                    }
                    return Optional.absent();
                }
            };
            final byte[] TOKEN_SECRET_KEY = bytesOf("MySecretKey");
            final JsonWebTokenParser tokenParser = new DefaultJsonWebTokenParser();
            final HmacSHA512Verifier tokenVerifier = new HmacSHA512Verifier(TOKEN_SECRET_KEY);
            register(AuthFactory.binder(new JWTAuthFactory<>(authenticator, "realm", String.class, tokenVerifier, tokenParser)));
            register(AuthResource.class);
        }
    }
}
