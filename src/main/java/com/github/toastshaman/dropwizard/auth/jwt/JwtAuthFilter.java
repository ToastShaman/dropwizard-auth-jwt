/*
 * 09/07/23 Matthew Donovan
 *  Updated imports to use jakarta.* instead of javax.* and updated code to support DropWizard 4.0.0
 */
package com.github.toastshaman.dropwizard.auth.jwt;

import io.dropwizard.auth.AuthFilter;
import io.dropwizard.auth.AuthenticationException;
import io.dropwizard.auth.Authenticator;
import jakarta.annotation.Priority;
import jakarta.ws.rs.InternalServerErrorException;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.Cookie;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.SecurityContext;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.security.Principal;
import java.util.Map;
import java.util.Optional;

import static com.google.common.base.Preconditions.checkNotNull;
import static jakarta.ws.rs.core.HttpHeaders.AUTHORIZATION;

@Priority(Priorities.AUTHENTICATION)
public class JwtAuthFilter<P extends Principal> extends AuthFilter<JwtContext, P> {

    private static final Logger LOGGER = LoggerFactory.getLogger(JwtAuthFilter.class);

    private final JwtConsumer consumer;
    private final String cookieName;

    private JwtAuthFilter(JwtConsumer consumer, String cookieName) {
        this.consumer = consumer;
        this.cookieName = cookieName;
    }

    @Override
    public void filter(final ContainerRequestContext requestContext) throws IOException {
        final Optional<String> optionalToken = getTokenFromCookieOrHeader(requestContext);

        if (optionalToken.isPresent()) {
            try {
                final JwtContext jwtContext = verifyToken(optionalToken.get());
                final Optional<P> principal = authenticator.authenticate(jwtContext);

                if (principal.isPresent()) {
                    requestContext.setSecurityContext(new SecurityContext() {

                        @Override
                        public Principal getUserPrincipal() {
                            return principal.get();
                        }

                        @Override
                        public boolean isUserInRole(String role) {
                            return authorizer.authorize(principal.get(), role, requestContext);
                        }

                        @Override
                        public boolean isSecure() {
                            return requestContext.getSecurityContext().isSecure();
                        }

                        @Override
                        public String getAuthenticationScheme() {
                            return SecurityContext.BASIC_AUTH;
                        }

                    });
                    return;
                }
            } catch (InvalidJwtException ex) {
                LOGGER.warn("Error decoding credentials: " + ex.getMessage(), ex);
            } catch (AuthenticationException ex) {
                LOGGER.warn("Error authenticating credentials", ex);
                throw new InternalServerErrorException();
            }
        }

        throw new WebApplicationException(unauthorizedHandler.buildResponse(prefix, realm));
    }

    private JwtContext verifyToken(String rawToken) throws InvalidJwtException {
        return consumer.process(rawToken);
    }

    private Optional<String> getTokenFromCookieOrHeader(ContainerRequestContext requestContext) {
        final Optional<String> headerToken = getTokenFromHeader(requestContext.getHeaders());
        return headerToken.isPresent() ? headerToken : getTokenFromCookie(requestContext);
    }

    private Optional<String> getTokenFromHeader(MultivaluedMap<String, String> headers) {
        final String header = headers.getFirst(AUTHORIZATION);
        if (header != null) {
            int space = header.indexOf(' ');
            if (space > 0) {
                final String method = header.substring(0, space);
                if (prefix.equalsIgnoreCase(method)) {
                    final String rawToken = header.substring(space + 1);
                    return Optional.of(rawToken);
                }
            }
        }

        return Optional.empty();
    }

    private Optional<String> getTokenFromCookie(ContainerRequestContext requestContext) {
        final Map<String, Cookie> cookies = requestContext.getCookies();

        if (cookieName != null && cookies.containsKey(cookieName)) {
            final Cookie tokenCookie = cookies.get(cookieName);
            final String rawToken = tokenCookie.getValue();
            return Optional.of(rawToken);
        }

        return Optional.empty();
    }

    /**
     * Builder for {@link JwtAuthFilter}.
     * <p>An {@link Authenticator} must be provided during the building process.</p>
     *
     * @param <P> the principal
     */
    public static class Builder<P extends Principal> extends AuthFilterBuilder<JwtContext, P, JwtAuthFilter<P>> {

        private JwtConsumer consumer;
        private String cookieName;

        public Builder<P> setJwtConsumer(JwtConsumer consumer) {
            this.consumer = consumer;
            return this;
        }

        public Builder<P> setCookieName(String cookieName) {
            this.cookieName = cookieName;
            return this;
        }

        @Override
        protected JwtAuthFilter<P> newInstance() {
            checkNotNull(consumer, "JwtConsumer is not set");
            return new JwtAuthFilter<>(consumer, cookieName);
        }
    }
}
