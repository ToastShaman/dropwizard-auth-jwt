package com.github.toastshaman.dropwizard.auth.jwt;

import com.codahale.metrics.MetricRegistry;
import com.github.toastshaman.dropwizard.auth.jwt.hmac.HmacSHA512Verifier;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebToken;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebTokenClaim;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebTokenHeader;
import com.github.toastshaman.dropwizard.auth.jwt.parser.DefaultJsonWebTokenParser;
import com.google.common.base.Optional;
import com.google.common.cache.CacheBuilderSpec;
import io.dropwizard.auth.Authenticator;
import io.dropwizard.auth.CachingAuthenticator;
import io.dropwizard.auth.PrincipalImpl;
import org.junit.Before;
import org.junit.Test;
import org.mockito.InOrder;

import java.security.Principal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.*;

public class JWTCachingAuthenticatorTest {

    @SuppressWarnings("unchecked")
    private final Authenticator<JsonWebToken, Principal> underlying = mock(Authenticator.class);

    private final CachingAuthenticator<JsonWebToken, Principal> cached =
        new CachingAuthenticator<>(new MetricRegistry(), underlying, CacheBuilderSpec.parse("maximumSize=1"));

    private final String SECRET = "Po70rBeXjKDhckY9yWmhNVte/UajN8xbA==lkDvaBTeWRja0SFMzcz113d/bi3Tn";
    private final String RAW_TOKEN = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJleHAiOjE0NDkwNjgyNzgsImlhdCI6MTQ0OTA0MzA3OCwic3ViIjoiLTIifQ.F_LrF9Q3SC3KIQL5UbLpxsA1_ZRi_SxRmBc5L0Qv3N8jzmY9pEY3vpLLHtqKRdeID9WcO_MB1iwYMVSHw4v7sg";

    private JsonWebToken tokenOne() {
        return JsonWebToken.builder()
            .header(JsonWebTokenHeader.HS512())
            .claim(JsonWebTokenClaim.builder()
                .subject("good-guy")
                .build()
            ).build();
    }

    private JsonWebToken tokenTwo() {
        return JsonWebToken.builder()
            .header(JsonWebTokenHeader.HS512())
            .claim(JsonWebTokenClaim.builder()
                .subject("good-guy-two")
                .build()
            ).build();
    }

    @Before
    public void setUp() throws Exception {
        when(underlying.authenticate(any(JsonWebToken.class)))
            .thenReturn(Optional.<Principal>of(new PrincipalImpl("principal")));
    }

    @Test
    public void compareTokens() throws Exception {
        JsonWebToken token1 = tokenOne();
        JsonWebToken token2 = tokenOne();
        JsonWebToken token3 = tokenTwo();
        JsonWebToken token4 = tokenTwo();
        // equals
        assertThat(token1).isEqualTo(token2);
        assertThat(token3).isEqualTo(token4);
        assertThat(token1).isNotEqualTo(token3);
        // hashcode
        assertThat(token1.hashCode()).isEqualTo(token2.hashCode());
        assertThat(token3.hashCode()).isEqualTo(token4.hashCode());
        assertThat(token1.hashCode()).isNotEqualTo(token3.hashCode());

        /* same story after auth workflow
        * 1. parse token
        * 2. verify token
        * 3. test equals and hashcode
        */
        JsonWebTokenParser tokenParser = new DefaultJsonWebTokenParser();
        HmacSHA512Verifier tokenVerifier = new HmacSHA512Verifier(SECRET.getBytes("UTF-8"));
        token1 = tokenParser.parse(RAW_TOKEN);
        token2 = tokenParser.parse(RAW_TOKEN);
        tokenVerifier.verifySignature(token1);
        tokenVerifier.verifySignature(token2);
        // equals
        assertThat(token1).isEqualTo(token2);
        // hashcode
        assertThat(token1.hashCode()).isEqualTo(token2.hashCode());
    }

    @Test
    public void cachesTheFirstReturnedPrincipal() throws Exception {
        assertThat(cached.authenticate(tokenOne())).isEqualTo(Optional.<Principal>of(new PrincipalImpl("principal")));
        assertThat(cached.authenticate(tokenOne())).isEqualTo(Optional.<Principal>of(new PrincipalImpl("principal")));

        verify(underlying, times(1)).authenticate(tokenOne());
    }

    @Test
    public void respectsTheCacheConfiguration() throws Exception {
        cached.authenticate(tokenOne());
        cached.authenticate(tokenTwo());
        cached.authenticate(tokenOne());

        final InOrder inOrder = inOrder(underlying);
        inOrder.verify(underlying, times(1)).authenticate(tokenOne());
        inOrder.verify(underlying, times(1)).authenticate(tokenTwo());
        inOrder.verify(underlying, times(1)).authenticate(tokenOne());
    }
}
