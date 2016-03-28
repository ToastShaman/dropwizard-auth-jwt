package com.github.toastshaman.dropwizard.auth.jwt;

import com.codahale.metrics.Meter;
import com.codahale.metrics.MetricRegistry;
import com.codahale.metrics.Timer;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheBuilderSpec;
import com.google.common.cache.CacheStats;
import io.dropwizard.auth.AuthenticationException;
import io.dropwizard.auth.Authenticator;
import org.jose4j.jwt.consumer.JwtContext;

import java.security.Principal;
import java.util.AbstractMap.SimpleEntry;
import java.util.Optional;
import java.util.function.Predicate;

import static com.codahale.metrics.MetricRegistry.name;

public class CachingJwtAuthenticator<P extends Principal> implements Authenticator<JwtContext, P> {

    private final Authenticator<JwtContext, P> authenticator;
    private final Cache<String, SimpleEntry<JwtContext, Optional<P>>> cache;
    private final Meter cacheMisses;
    private final Timer gets;

    /**
     * Creates a new cached authenticator.
     *
     * @param metricRegistry the application's registry of metrics
     * @param authenticator  the underlying authenticator
     * @param cacheSpec      a {@link CacheBuilderSpec}
     */
    public CachingJwtAuthenticator(final MetricRegistry metricRegistry,
                                   final Authenticator<JwtContext, P> authenticator,
                                   final CacheBuilderSpec cacheSpec) {
        this(metricRegistry, authenticator, CacheBuilder.from(cacheSpec));
    }

    /**
     * Creates a new cached authenticator.
     *
     * @param metricRegistry the application's registry of metrics
     * @param authenticator  the underlying authenticator
     * @param builder        a {@link CacheBuilder}
     */
    public CachingJwtAuthenticator(final MetricRegistry metricRegistry,
                                   final Authenticator<JwtContext, P> authenticator,
                                   final CacheBuilder<Object, Object> builder) {
        this.authenticator = authenticator;
        this.cacheMisses = metricRegistry.meter(name(authenticator.getClass(), "cache-misses"));
        this.gets = metricRegistry.timer(name(authenticator.getClass(), "gets"));
        this.cache = builder.recordStats().build();
    }

    @Override
    public Optional<P> authenticate(JwtContext context) throws AuthenticationException {
        final Timer.Context timer = gets.time();
        try {
            final SimpleEntry<JwtContext, Optional<P>> cacheEntry = cache.getIfPresent(context.getJwt());
            if (cacheEntry != null) {
                return cacheEntry.getValue();
            }

            cacheMisses.mark();
            final Optional<P> principal = authenticator.authenticate(context);
            if (principal.isPresent()) {
                cache.put(context.getJwt(), new SimpleEntry<>(context, principal));
            }
            return principal;
        }
        finally { timer.stop(); }
    }

    /**
     * Discards any cached principal for the given credentials.
     *
     * @param credentials a set of credentials
     */
    public void invalidate(JwtContext credentials) {
        cache.invalidate(credentials.getJwt());
    }

    /**
     * Discards any cached principal for the given collection of credentials.
     *
     * @param credentials a collection of credentials
     */
    public void invalidateAll(Iterable<JwtContext> credentials) {
        credentials.forEach(context -> cache.invalidate(context.getJwt()));
    }

    /**
     * Discards any cached principal for the collection of credentials satisfying the given predicate.
     *
     * @param predicate a predicate to filter credentials
     */
    public void invalidateAll(Predicate<? super JwtContext> predicate) {
        cache.asMap().entrySet().stream()
            .map(entry -> entry.getValue().getKey())
            .filter(predicate::test)
            .map(JwtContext::getJwt)
            .forEach(cache::invalidate);
    }

    /**
     * Discards all cached principals.
     */
    public void invalidateAll() {
        cache.invalidateAll();
    }

    /**
     * Returns the number of cached principals.
     *
     * @return the number of cached principals
     */
    public long size() {
        return cache.size();
    }

    /**
     * Returns a set of statistics about the cache contents and usage.
     *
     * @return a set of statistics about the cache contents and usage
     */
    public CacheStats stats() {
        return cache.stats();
    }
}
