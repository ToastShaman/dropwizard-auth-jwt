package com.github.toastshaman.dropwizard.auth.jwt;

import com.google.common.base.Throwables;
import com.google.common.collect.ImmutableList;
import io.dropwizard.jersey.DropwizardResourceConfig;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.keys.HmacKey;
import org.jose4j.lang.JoseException;
import org.junit.Test;

import javax.ws.rs.WebApplicationException;
import javax.ws.rs.container.ContainerRequestFilter;

import static com.google.common.base.Charsets.UTF_8;
import static javax.ws.rs.core.HttpHeaders.AUTHORIZATION;
import static javax.ws.rs.core.HttpHeaders.WWW_AUTHENTICATE;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.failBecauseExceptionWasNotThrown;
import static org.jose4j.jws.AlgorithmIdentifiers.HMAC_SHA512;

public class JwtAuthProviderTest extends AuthBaseTest<JwtAuthProviderTest.JwtAuthTestResourceConfig> {

    private static final String SECRET_KEY = "MySecretKey";

    static class JwtAuthTestResourceConfig extends AuthBaseResourceConfig {
        protected ContainerRequestFilter getAuthFilter() {

            final JwtConsumer consumer = new JwtConsumerBuilder()
                .setRequireExpirationTime() // the JWT must have an expiration time
                .setAllowedClockSkewInSeconds(30) // allow some leeway in validating time based claims to account for clock skew
                .setRequireSubject() // the JWT must have a subject claim
                .setExpectedIssuer("Issuer") // whom the JWT needs to have been issued by
                .setExpectedAudience("Audience") // whom the JWT needs to have been issued by
                .setVerificationKey(new HmacKey(SECRET_KEY.getBytes(UTF_8))) // verify the signature with the public key
                .setRelaxVerificationKeyValidation() // relaxes key length requirement
                .build();// create the JwtConsumer instance

            return new JwtAuthFilter.Builder<>()
                .setCookieName(COOKIE_NAME)
                .setJwtConsumer(consumer)
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
                .header(AUTHORIZATION, getPrefix() + " " + getInvalidToken())
                .get(String.class);
            failBecauseExceptionWasNotThrown(WebApplicationException.class);
        } catch (WebApplicationException e) {
            assertThat(e.getResponse().getStatus()).isEqualTo(401);
            assertThat(e.getResponse().getHeaders().get(WWW_AUTHENTICATE)).containsOnly(getPrefix() + " realm=\"realm\"");
        }
    }

    @Test
    public void respondsToExpiredTokensWith401() throws Exception {
        try {
            target("/test/admin").request()
                .header(AUTHORIZATION, getPrefix() + " " + getOrdinaryGuyExpiredToken())
                .get(String.class);
            failBecauseExceptionWasNotThrown(WebApplicationException.class);
        } catch (WebApplicationException e) {
            assertThat(e.getResponse().getStatus()).isEqualTo(401);
            assertThat(e.getResponse().getHeaders().get(WWW_AUTHENTICATE)).containsOnly(getPrefix() + " realm=\"realm\"");
        }
    }

    @Override
    protected DropwizardResourceConfig getDropwizardResourceConfig() {
        return new JwtAuthTestResourceConfig();
    }

    @Override
    protected Class<JwtAuthTestResourceConfig> getDropwizardResourceConfigClass() {
        return JwtAuthTestResourceConfig.class;
    }

    @Override
    protected String getPrefix() {
        return BEARER_PREFIX;
    }

    @Override
    protected String getOrdinaryGuyValidToken() {
        return toToken(withKey(SECRET_KEY), claimsForUser(ORDINARY_USER));
    }

    @Override
    protected String getOrdinaryGuyExpiredToken() {
        final JwtClaims claims = claimsForUser(ORDINARY_USER);
        claims.setExpirationTime(NumericDate.fromSeconds(-10));
        return toToken(withKey(SECRET_KEY), claims);
    }

    @Override
    protected String getGoodGuyValidToken() {
        return toToken(withKey(SECRET_KEY), claimsForUser(ADMIN_USER));
    }

    @Override
    protected String getBadGuyToken() {
        return toToken(withKey(SECRET_KEY), claimsForUser(BADGUY_USER));
    }

    @Override
    protected String getInvalidToken() {
        return toToken(withKey("DERP"), claimsForUser(BADGUY_USER));
    }

    private JwtClaims claimsForUser(String user) {
        final JwtClaims claims = new JwtClaims();
        claims.setExpirationTimeMinutesInTheFuture(5);
        claims.setSubject(user);
        claims.setIssuer("Issuer");
        claims.setAudience("Audience");
        return claims;
    }

    private String toToken(byte[] key, JwtClaims claims) {
        final JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setAlgorithmHeaderValue(HMAC_SHA512);
        jws.setKey(new HmacKey(key));
        jws.setDoKeyValidation(false);

        try {
            return jws.getCompactSerialization();
        }
        catch (JoseException e) { throw Throwables.propagate(e); }
    }

    private byte[] withKey(String key) {
        return key.getBytes(UTF_8);
    }
}
