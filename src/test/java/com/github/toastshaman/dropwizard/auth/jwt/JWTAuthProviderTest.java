package com.github.toastshaman.dropwizard.auth.jwt;

import com.codahale.metrics.MetricRegistry;
import com.github.toastshaman.dropwizard.auth.jwt.hmac.HmacSHA512Signer;
import com.github.toastshaman.dropwizard.auth.jwt.hmac.HmacSHA512Verifier;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebToken;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebTokenClaim;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebTokenHeader;
import com.google.common.base.Optional;
import com.sun.jersey.api.client.UniformInterfaceException;
import com.sun.jersey.test.framework.AppDescriptor;
import com.sun.jersey.test.framework.JerseyTest;
import com.sun.jersey.test.framework.LowLevelAppDescriptor;
import io.dropwizard.auth.Auth;
import io.dropwizard.auth.AuthenticationException;
import io.dropwizard.auth.Authenticator;
import io.dropwizard.jersey.DropwizardResourceConfig;
import io.dropwizard.logging.LoggingFactory;
import org.junit.Test;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;

import static com.github.toastshaman.dropwizard.auth.jwt.JsonWebTokenUtils.bytesOf;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.fail;

public class JWTAuthProviderTest extends JerseyTest {

    static { LoggingFactory.bootstrap(); }

    @Path("/test/")
    @Produces(MediaType.TEXT_PLAIN)
    public static class ExampleResource {
        @GET public String show(@Auth String principal) { return principal; }
    }

    @Override
    protected AppDescriptor configure() {
        final byte[] TOKEN_SECRET_KEY = bytesOf("MySecretKey");
        final DropwizardResourceConfig config = DropwizardResourceConfig.forTesting(new MetricRegistry());
        final Authenticator<JsonWebToken, String> authenticator = new Authenticator<JsonWebToken, String>() {
            @Override
            public Optional<String> authenticate(JsonWebToken credentials) throws AuthenticationException {
                if ("good-guy".equals(credentials.claim().getParameter("principal"))) {
                    return Optional.of("good-guy");
                }
                if ("bad-guy".equals(credentials.claim().getParameter("principal"))) {
                    throw new AuthenticationException("CRAP", new RuntimeException(""));
                }
                return Optional.absent();
            }
        };
        final HmacSHA512Verifier tokenVerifier = new HmacSHA512Verifier(TOKEN_SECRET_KEY);
        config.getSingletons().add(new JWTAuthProvider<>(authenticator, tokenVerifier, "realm"));
        config.getSingletons().add(new ExampleResource());
        return new LowLevelAppDescriptor.Builder(config).build();
    }

    @Test
    public void respondsToMissingCredentialsWith401() throws Exception {
        try {
            client().resource("/test").get(String.class);
            fail("An UniformInterfaceException.class exception should have been thrown");
        } catch (UniformInterfaceException e) {
            assertThat(e.getResponse().getStatus(), equalTo(401));
            assertThat(e.getResponse().getHeaders().get(HttpHeaders.WWW_AUTHENTICATE), contains(equalTo("Bearer realm=\"realm\"")));
        }
    }

    @Test
    public void transformsCredentialsToPrincipals() throws Exception {
        final byte[] TOKEN_SECRET_KEY = bytesOf("MySecretKey");
        final HmacSHA512Signer signer = new HmacSHA512Signer(TOKEN_SECRET_KEY);
        final JsonWebToken token = JsonWebToken.builder().header(JsonWebTokenHeader.HS512()).claim(JsonWebTokenClaim.builder().param("principal", "good-guy").build()).build();
        final String signedToken = signer.sign(token);

        assertThat(client().resource("/test").header(HttpHeaders.AUTHORIZATION, "Bearer " + signedToken).get(String.class), equalTo("good-guy"));
    }

    @Test
    public void respondsToNonBasicCredentialsWith401() throws Exception {
        try {
            client().resource("/test").header(HttpHeaders.AUTHORIZATION, "Derp WHEE").get(String.class);
            fail("An UniformInterfaceException.class exception should have been thrown");
        } catch (UniformInterfaceException e) {
            assertThat(e.getResponse().getStatus(), equalTo(401));
            assertThat(e.getResponse().getHeaders().get(HttpHeaders.WWW_AUTHENTICATE), contains(equalTo("Bearer realm=\"realm\"")));
        }
    }

    @Test
    public void respondsToInvalidSignaturesWith500() throws Exception {
        try {
            final byte[] TOKEN_SECRET_KEY = bytesOf("DIFFERENT_KEY");
            final HmacSHA512Signer signer = new HmacSHA512Signer(TOKEN_SECRET_KEY);
            final JsonWebToken token = JsonWebToken.builder().header(JsonWebTokenHeader.HS512()).claim(JsonWebTokenClaim.builder().param("principal", "good-guy").build()).build();
            final String signedToken = signer.sign(token);

            client().resource("/test").header(HttpHeaders.AUTHORIZATION, "Bearer " + signedToken).get(String.class);

            fail("An UniformInterfaceException.class exception should have been thrown");
        } catch (UniformInterfaceException e) {
            assertThat(e.getResponse().getStatus(), equalTo(500));
        }
    }

    @Test
    public void respondsToExceptionsWith500() throws Exception {
        try {
            final byte[] TOKEN_SECRET_KEY = bytesOf("MySecretKey");
            final HmacSHA512Signer signer = new HmacSHA512Signer(TOKEN_SECRET_KEY);
            final JsonWebToken token = JsonWebToken.builder().header(JsonWebTokenHeader.HS512()).claim(JsonWebTokenClaim.builder().param("principal", "bad-guy").build()).build();
            final String signedToken = signer.sign(token);

            client().resource("/test").header(HttpHeaders.AUTHORIZATION, "Bearer " + signedToken).get(String.class);
            fail("An UniformInterfaceException.class exception should have been thrown");
        } catch (UniformInterfaceException e) {
            assertThat(e.getResponse().getStatus(), equalTo(500));
        }
    }
}
