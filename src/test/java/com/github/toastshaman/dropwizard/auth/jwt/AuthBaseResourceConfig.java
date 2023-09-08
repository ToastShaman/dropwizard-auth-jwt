package com.github.toastshaman.dropwizard.auth.jwt;

import com.codahale.metrics.MetricRegistry;
import io.dropwizard.auth.AuthDynamicFeature;
import io.dropwizard.auth.AuthValueFactoryProvider;
import io.dropwizard.jersey.DropwizardResourceConfig;
import jakarta.ws.rs.container.ContainerRequestFilter;
import org.glassfish.jersey.server.filter.RolesAllowedDynamicFeature;

import java.security.Principal;

public abstract class AuthBaseResourceConfig extends DropwizardResourceConfig {
    public AuthBaseResourceConfig() {
        super();

        register(new AuthDynamicFeature(getAuthFilter()));
        register(new AuthValueFactoryProvider.Binder<>(Principal.class));
        register(RolesAllowedDynamicFeature.class);
        register(AuthResource.class);
    }

    protected abstract ContainerRequestFilter getAuthFilter();
}