package com.github.toastshaman.dropwizard.auth.jwt;

import com.github.toastshaman.dropwizard.auth.jwt.exceptions.JsonWebTokenException;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebToken;
import com.google.common.base.Optional;
import com.google.common.base.Preconditions;
import io.dropwizard.auth.AuthFilter;
import io.dropwizard.auth.AuthenticationException;
import io.dropwizard.auth.Authenticator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Priority;
import javax.ws.rs.InternalServerErrorException;
import javax.ws.rs.Priorities;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.SecurityContext;
import java.io.IOException;
import java.security.Principal;

@Priority(Priorities.AUTHENTICATION)
public class JWTAuthFilter<P extends Principal> extends AuthFilter<JsonWebToken, P> {

    private static final Logger LOGGER = LoggerFactory.getLogger(JWTAuthFilter.class);

    private final JsonWebTokenVerifier tokenVerifier;
    private final JsonWebTokenParser tokenParser;

    private JWTAuthFilter(JsonWebTokenParser tokenParser, JsonWebTokenVerifier tokenVerifier) {
        this.tokenParser = tokenParser;
        this.tokenVerifier = tokenVerifier;
    }

    @Override
    public void filter(final ContainerRequestContext requestContext) throws IOException {
        final String header = requestContext.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (header != null) {
            final int space = header.indexOf(' ');
            if (space > 0) {
                final String method = header.substring(0, space);
                if (prefix.equalsIgnoreCase(method)) {
                    try {
                        final String rawToken = header.substring(space + 1);
                        final JsonWebToken token = tokenParser.parse(rawToken);

                        tokenVerifier.verifySignature(token);

                        final Optional<P> principal = authenticator.authenticate(token);
                        if (principal.isPresent()) {
                            requestContext.setSecurityContext(new SecurityContext() {
                                @Override
                                public Principal getUserPrincipal() {
                                    return principal.get();
                                }

                                @Override
                                public boolean isUserInRole(String role) {
                                    return authorizer.authorize(principal.get(), role);
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
                    } catch (JsonWebTokenException e) {
                        LOGGER.warn("Error decoding credentials: " + e.getMessage(), e);
                    } catch (AuthenticationException e) {
                        LOGGER.warn("Error authenticating credentials", e);
                        throw new InternalServerErrorException();
                    }
                }
            }
        }

        throw new WebApplicationException(unauthorizedHandler.buildResponse(prefix, realm));
    }

    /**
     * Builder for {@link JWTAuthFilter}.
     * <p>An {@link Authenticator} must be provided during the building process.</p>
     *
     * @param <P> the principal
     */
    public static class Builder<P extends Principal> extends AuthFilterBuilder<JsonWebToken, P, JWTAuthFilter<P>> {

        private JsonWebTokenParser parser;
        private JsonWebTokenVerifier verifier;

        public Builder<P> setTokenParser(JsonWebTokenParser parser) {
            this.parser = parser;
            return this;
        }

        public Builder<P> setTokenVerifier(JsonWebTokenVerifier verifier) {
            this.verifier = verifier;
            return this;
        }

        @Override
        protected JWTAuthFilter<P> newInstance() {
            Preconditions.checkArgument(parser != null, "JsonWebTokenParser is not set");
            Preconditions.checkArgument(verifier != null, "JsonWebTokenVerifier is not set");
            return new JWTAuthFilter<>(parser, verifier);
        }
    }
}
