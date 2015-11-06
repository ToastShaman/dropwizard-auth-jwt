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
import javax.ws.rs.core.Cookie;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.SecurityContext;
import java.io.IOException;
import java.security.Principal;
import java.util.Map;

@Priority(Priorities.AUTHENTICATION)
public class JWTAuthFilter<P extends Principal> extends AuthFilter<JsonWebToken, P> {

    private static final Logger LOGGER = LoggerFactory.getLogger(JWTAuthFilter.class);

    private final JsonWebTokenVerifier tokenVerifier;
    private final JsonWebTokenParser tokenParser;
    private final String cookieName;

    private JWTAuthFilter(JsonWebTokenParser tokenParser, JsonWebTokenVerifier tokenVerifier, String cookieName) {
        this.tokenParser = tokenParser;
        this.tokenVerifier = tokenVerifier;
        this.cookieName = cookieName;
    }

    @Override
    public void filter(final ContainerRequestContext requestContext) throws IOException {
        Optional<String> optionalToken = getTokenFromCookieOrHeader(requestContext);

        if (optionalToken.isPresent()) {
            try {
                final JsonWebToken token = verifiedToken(optionalToken);
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
            }
            catch (JsonWebTokenException ex) {
                LOGGER.warn("Error decoding credentials: " + ex.getMessage(), ex);
            }
            catch (AuthenticationException ex) {
                LOGGER.warn("Error authenticating credentials", ex);
                throw new InternalServerErrorException();
            }
        }

        throw new WebApplicationException(unauthorizedHandler.buildResponse(prefix, realm));
    }

    private JsonWebToken verifiedToken(Optional<String> optionalToken) {
        final String rawToken = optionalToken.get();
        final JsonWebToken token = tokenParser.parse(rawToken);
        tokenVerifier.verifySignature(token);
        return token;
    }

    public Optional<String> getTokenFromCookieOrHeader(ContainerRequestContext requestContext) {
        Optional<String> headerToken = getTokenFromHeader(requestContext.getHeaders());

        if (headerToken.isPresent()) {
            return headerToken;
        }
        else {
            Optional<String> cookieToken = getTokenFromCookie(requestContext);

            if (cookieToken.isPresent()) {
                return cookieToken;
            }
            else {
                return Optional.absent();
            }
        }
    }

    private Optional<String> getTokenFromHeader(MultivaluedMap<String, String> headers) {
        String header = headers.getFirst(HttpHeaders.AUTHORIZATION);
        if (header != null) {
            int space = header.indexOf(' ');
            if (space > 0) {
                String method = header.substring(0, space);
                if (prefix.equalsIgnoreCase(method)) {
                    String rawToken = header.substring(space + 1);
                    return Optional.of(rawToken);
                }
            }
        }

        return Optional.absent();
    }

    public Optional<String> getTokenFromCookie(ContainerRequestContext requestContext) {
        Map<String, Cookie> cookies = requestContext.getCookies();

        if (cookieName != null && cookies.containsKey(cookieName)) {
            Cookie tokenCookie = cookies.get(cookieName);
            String rawToken = tokenCookie.getValue();

            return Optional.of(rawToken);
        }

        return Optional.absent();
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
        private String cookieName;

        public Builder<P> setTokenParser(JsonWebTokenParser parser) {
            this.parser = parser;
            return this;
        }

        public Builder<P> setTokenVerifier(JsonWebTokenVerifier verifier) {
            this.verifier = verifier;
            return this;
        }

        public Builder<P> setCookieName(String cookieName) {
            this.cookieName = cookieName;
            return this;
        }

        @Override
        protected JWTAuthFilter<P> newInstance() {
            Preconditions.checkArgument(parser != null, "JsonWebTokenParser is not set");
            Preconditions.checkArgument(verifier != null, "JsonWebTokenVerifier is not set");
            return new JWTAuthFilter<>(parser, verifier, cookieName);
        }
    }

}
