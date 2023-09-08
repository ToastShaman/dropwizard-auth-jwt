/*
 * 09/07/23 Matthew Donovan
 *  Updated imports to use jakarta.* instead of javax.* and updated code to support DropWizard 4.0.0
 */
package com.github.toastshaman.dropwizard.auth.jwt;

import io.dropwizard.jersey.DropwizardResourceConfig;
import io.dropwizard.logging.common.BootstrapLogging;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.HttpHeaders;
import org.glassfish.jersey.test.DeploymentContext;
import org.glassfish.jersey.test.JerseyTest;
import org.glassfish.jersey.test.ServletDeploymentContext;
import org.glassfish.jersey.test.TestProperties;
import org.glassfish.jersey.test.grizzly.GrizzlyWebTestContainerFactory;
import org.glassfish.jersey.test.spi.TestContainerException;
import org.glassfish.jersey.test.spi.TestContainerFactory;
import org.junit.Test;

import static jakarta.ws.rs.core.HttpHeaders.AUTHORIZATION;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.failBecauseExceptionWasNotThrown;
import static org.glassfish.jersey.servlet.ServletProperties.JAXRS_APPLICATION_CLASS;

public abstract class AuthBaseTest<T extends DropwizardResourceConfig> extends JerseyTest {

    protected static final String ADMIN_ROLE = "ADMIN";
    protected static final String ADMIN_USER = "good-guy";
    protected static final String ORDINARY_USER = "ordinary-guy";
    protected static final String BADGUY_USER = "bad-guy";
    protected static final String BEARER_PREFIX = "Bearer";
    protected static final String COOKIE_NAME = "jwt-token";

    static {
        BootstrapLogging.bootstrap();
    }

    @Override
    protected TestContainerFactory getTestContainerFactory() throws TestContainerException {
        return new GrizzlyWebTestContainerFactory();
    }

    protected abstract DropwizardResourceConfig getDropwizardResourceConfig();
    protected abstract Class<T> getDropwizardResourceConfigClass();
    protected abstract String getPrefix();

    protected abstract String getOrdinaryGuyValidToken();
    protected abstract String getOrdinaryGuyExpiredToken();
    protected abstract String getGoodGuyValidToken();
    protected abstract String getBadGuyToken();
    protected abstract String getInvalidToken();

    @Override
    protected DeploymentContext configureDeployment() {
        forceSet(TestProperties.CONTAINER_PORT, "0");

        return ServletDeploymentContext.builder(getDropwizardResourceConfig())
            .initParam(JAXRS_APPLICATION_CLASS, getDropwizardResourceConfigClass().getName())
            .build();
    }

    @Test
    public void respondsToMissingCredentialsWith401() throws Exception {
        try {
            target("/test/admin").request().get(String.class);
            failBecauseExceptionWasNotThrown(WebApplicationException.class);
        } catch (WebApplicationException e) {
            assertThat(e.getResponse().getStatus()).isEqualTo(401);
            assertThat(e.getResponse().getHeaders().get(HttpHeaders.WWW_AUTHENTICATE))
                .containsOnly(getPrefix() + " realm=\"realm\"");
        }
    }

    @Test
    public void resourceWithoutAuth200() {
        assertThat(target("/test/noauth").request()
            .get(String.class))
            .isEqualTo("hello");
    }

    @Test
    public void resourceWithAuthenticationWithoutAuthorizationWithCorrectCredentials200() {
        assertThat(target("/test/profile").request()
            .header(AUTHORIZATION, getPrefix() + " " + getOrdinaryGuyValidToken())
            .get(String.class))
            .isEqualTo("'" + ORDINARY_USER + "' has user privileges");
    }

    @Test
    public void respondsToExpiredCredentialsWith401() {
        try {
            target("/test/profile").request()
                .header(AUTHORIZATION, getPrefix() + " " + getOrdinaryGuyExpiredToken())
                .get(String.class);
            failBecauseExceptionWasNotThrown(WebApplicationException.class);
        } catch (WebApplicationException e) {
            assertThat(e.getResponse().getStatus()).isEqualTo(401);
        }
    }

    @Test
    public void resourceWithAuthenticationWithoutAuthorizationNoCredentials401() {
        try {
            target("/test/profile").request().get(String.class);
            failBecauseExceptionWasNotThrown(WebApplicationException.class);
        } catch (WebApplicationException e) {
            assertThat(e.getResponse().getStatus()).isEqualTo(401);
            assertThat(e.getResponse().getHeaders().get(HttpHeaders.WWW_AUTHENTICATE))
                .containsOnly(getPrefix() + " realm=\"realm\"");
        }
    }

    @Test
    public void resourceWithAuthorizationPrincipalIsNotAuthorized403() {
        try {
            target("/test/admin").request()
                .header(AUTHORIZATION, getPrefix() + " " + getOrdinaryGuyValidToken())
                .get(String.class);
            failBecauseExceptionWasNotThrown(WebApplicationException.class);
        } catch (WebApplicationException e) {
            assertThat(e.getResponse().getStatus()).isEqualTo(403);
        }
    }

    @Test
    public void resourceWithDenyAllAndNoAuth401() {
        try {
            target("/test/denied").request().get(String.class);
            failBecauseExceptionWasNotThrown(WebApplicationException.class);
        } catch (WebApplicationException e) {
            assertThat(e.getResponse().getStatus()).isEqualTo(401);
        }
    }

    @Test
    public void resourceWithDenyAllAndAuth403() {
        try {
            target("/test/denied").request()
                .header(AUTHORIZATION, getPrefix() + " " + getGoodGuyValidToken())
                .get(String.class);
            failBecauseExceptionWasNotThrown(WebApplicationException.class);
        } catch (WebApplicationException e) {
            assertThat(e.getResponse().getStatus()).isEqualTo(403);
        }
    }

    @Test
    public void transformsCredentialsToPrincipals() throws Exception {
        assertThat(target("/test/admin").request()
            .header(AUTHORIZATION, getPrefix() + " " + getGoodGuyValidToken())
            .get(String.class))
            .isEqualTo("'" + ADMIN_USER + "' has admin privileges");
    }

    @Test
    public void transformsCredentialsToPrincipalsWithCookie() throws Exception {
        assertThat(target("/test/admin").request()
            .cookie(COOKIE_NAME, getGoodGuyValidToken())
            .get(String.class))
            .isEqualTo("'" + ADMIN_USER + "' has admin privileges");
    }

    @Test
    public void transformsCredentialsToPrincipalsWhenAuthAnnotationExistsWithoutMethodAnnotation() throws Exception {
        assertThat(target("/test/implicit-permitall").request()
            .header(AUTHORIZATION, getPrefix() + " " + getGoodGuyValidToken())
            .get(String.class))
            .isEqualTo("'" + ADMIN_USER + "' has user privileges");
    }

    @Test
    public void respondsToNonBasicCredentialsWith401() throws Exception {
        try {
            target("/test/admin").request()
                .header(AUTHORIZATION, "Derp irrelevant")
                .get(String.class);
            failBecauseExceptionWasNotThrown(WebApplicationException.class);
        } catch (WebApplicationException e) {
            assertThat(e.getResponse().getStatus()).isEqualTo(401);
            assertThat(e.getResponse().getHeaders().get(HttpHeaders.WWW_AUTHENTICATE))
                .containsOnly(getPrefix() + " realm=\"realm\"");
        }
    }

    @Test
    public void respondsToExceptionsWith500() throws Exception {
        try {
            target("/test/admin").request()
                .header(AUTHORIZATION, getPrefix() + " " + getBadGuyToken())
                .get(String.class);
            failBecauseExceptionWasNotThrown(WebApplicationException.class);
        } catch (WebApplicationException e) {
            assertThat(e.getResponse().getStatus()).isEqualTo(500);
        }
    }
}