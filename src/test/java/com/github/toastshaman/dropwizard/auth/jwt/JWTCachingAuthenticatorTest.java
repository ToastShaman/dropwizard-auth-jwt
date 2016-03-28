package com.github.toastshaman.dropwizard.auth.jwt;

import com.codahale.metrics.MetricRegistry;
import com.google.common.base.Throwables;
import com.google.common.cache.CacheBuilderSpec;
import io.dropwizard.auth.Authenticator;
import io.dropwizard.auth.PrincipalImpl;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.jwt.consumer.JwtContext;
import org.jose4j.keys.HmacKey;
import org.junit.Before;
import org.junit.Test;

import java.security.Principal;
import java.util.Optional;

import static com.google.common.base.Charsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.*;

public class JwtCachingAuthenticatorTest {

    @SuppressWarnings("unchecked")
    private final Authenticator<JwtContext, Principal> underlying = mock(Authenticator.class);

    private final CachingJwtAuthenticator<Principal> cached = new CachingJwtAuthenticator<>(new MetricRegistry(),
        underlying, CacheBuilderSpec.parse("maximumSize=1"));

    private final String SECRET = "Po70rBeXjKDhckY9yWmhNVte/UajN8xbA==lkDvaBTeWRja0SFMzcz113d/bi3Tn";

    private final JwtConsumer consumer = new JwtConsumerBuilder()
        .setAllowedClockSkewInSeconds(30) // allow some leeway in validating time based claims to account for clock skew
        .setRequireSubject() // the JWT must have a subject claim
        .setExpectedIssuer("Issuer") // whom the JWT needs to have been issued by
        .setExpectedAudience("Audience") // whom the JWT needs to have been issued by
        .setVerificationKey(new HmacKey(SECRET.getBytes(UTF_8))) // verify the signature with the public key
        .setRelaxVerificationKeyValidation() // relaxes key length requirement
        .build();// create the JwtConsumer instance

    private JwtContext tokenOne() {
        final JwtClaims claims = new JwtClaims();
        claims.setSubject("good-guy");
        claims.setIssuer("Issuer");
        claims.setAudience("Audience");

        final JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.HMAC_SHA512);
        jws.setKey(new HmacKey(SECRET.getBytes(UTF_8)));
        jws.setDoKeyValidation(false);

        try {
            return consumer.process(jws.getCompactSerialization());
        }
        catch (Exception e) { throw Throwables.propagate(e); }
    }

    private JwtContext tokenTwo() {
        final JwtClaims claims = new JwtClaims();
        claims.setSubject("good-guy-two");
        claims.setIssuer("Issuer");
        claims.setAudience("Audience");

        final JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.HMAC_SHA512);
        jws.setKey(new HmacKey(SECRET.getBytes(UTF_8)));
        jws.setDoKeyValidation(false);

        try {
            return consumer.process(jws.getCompactSerialization());
        }
        catch (Exception e) { throw Throwables.propagate(e); }
    }

    @Before
    public void setUp() throws Exception {
        when(underlying.authenticate(any(JwtContext.class)))
            .thenReturn(Optional.<Principal>of(new PrincipalImpl("principal")));
    }

    @Test
    public void cachesTheFirstReturnedPrincipal() throws Exception {
        assertThat(cached.authenticate(tokenOne())).isEqualTo(Optional.<Principal>of(new PrincipalImpl("principal")));
        assertThat(cached.authenticate(tokenOne())).isEqualTo(Optional.<Principal>of(new PrincipalImpl("principal")));

        verify(underlying, times(1)).authenticate(any(JwtContext.class));
    }

    @Test
    public void doesNotCacheDifferingTokens() throws Exception {
        assertThat(cached.authenticate(tokenOne())).isEqualTo(Optional.<Principal>of(new PrincipalImpl("principal")));
        assertThat(cached.authenticate(tokenTwo())).isEqualTo(Optional.<Principal>of(new PrincipalImpl("principal")));

        verify(underlying, times(2)).authenticate(any(JwtContext.class));
    }
}
