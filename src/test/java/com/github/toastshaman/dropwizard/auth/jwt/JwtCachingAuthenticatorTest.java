package com.github.toastshaman.dropwizard.auth.jwt;

import com.codahale.metrics.MetricRegistry;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebToken;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebTokenClaim;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebTokenHeader;
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

    private JsonWebToken tokenOne() {
        return JsonWebToken.builder()
            .header(JsonWebTokenHeader.HS256())
            .claim(JsonWebTokenClaim.builder()
                .subject("good-guy")
                .build()
            ).build();
    }

    private JsonWebToken tokenTwo() {
        return JsonWebToken.builder()
            .header(JsonWebTokenHeader.HS256())
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
