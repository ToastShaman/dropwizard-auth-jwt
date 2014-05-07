package com.github.toastshaman.dropwizard.auth.jwt;

import com.github.toastshaman.dropwizard.auth.jwt.exceptions.InvalidSignatureException;
import com.github.toastshaman.dropwizard.auth.jwt.exceptions.JsonWebTokenException;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebToken;
import com.github.toastshaman.dropwizard.auth.jwt.parser.DefaultJsonWebTokenParser;
import com.google.common.base.Optional;
import com.sun.jersey.api.core.HttpContext;
import com.sun.jersey.api.model.Parameter;
import com.sun.jersey.core.spi.component.ComponentContext;
import com.sun.jersey.core.spi.component.ComponentScope;
import com.sun.jersey.server.impl.inject.AbstractHttpContextInjectable;
import com.sun.jersey.spi.inject.Injectable;
import com.sun.jersey.spi.inject.InjectableProvider;
import io.dropwizard.auth.Auth;
import io.dropwizard.auth.AuthenticationException;
import io.dropwizard.auth.Authenticator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

/**
 * A Jersey provider for JWT bearer tokens.
 *
 * @param <T> the principal type
 */
public class JWTAuthProvider<T> implements InjectableProvider<Auth, Parameter> {

    private static class JWTAuthInjectable<T> extends AbstractHttpContextInjectable<T> {
        private static final Logger LOGGER = LoggerFactory.getLogger(JWTAuthInjectable.class);
        private static final String CHALLENGE_FORMAT = "Bearer realm=\"%s\"";
        private static final String PREFIX = "bearer";

        private final Authenticator<JsonWebToken, T> authenticator;
        private final String realm;
        private final boolean required;

        private final JsonWebTokenVerifier tokenVerifier;
        private final DefaultJsonWebTokenParser tokenParser = new DefaultJsonWebTokenParser();

        private JWTAuthInjectable(Authenticator<JsonWebToken, T> authenticator,
                                JsonWebTokenVerifier tokenVerifier,
                                String realm,
                                boolean required) {
            this.authenticator = authenticator;
            this.tokenVerifier = tokenVerifier;
            this.realm = realm;
            this.required = required;
        }

        @Override
        public T getValue(HttpContext c) {
            try {
                final String header = c.getRequest().getHeaderValue(HttpHeaders.AUTHORIZATION);
                if (header != null) {
                    final int space = header.indexOf(' ');
                    if (space > 0) {
                        final String method = header.substring(0, space);
                        if (PREFIX.equalsIgnoreCase(method)) {
                            final String rawToken = header.substring(space + 1);

                            JsonWebToken token = null;

                            try {
                                token = tokenParser.parse(rawToken);
                                tokenVerifier.verifySignature(token);
                            } catch (InvalidSignatureException e) {
                                return null;
                            } catch (Exception e) {
                                throw new AuthenticationException(e.getMessage(), e);
                            }

                            final Optional<T> result = authenticator.authenticate(token);

                            if (result.isPresent()) {
                                return result.get();
                            }
                        }
                    }
                }
            } catch (AuthenticationException e) {
                LOGGER.warn("Error authenticating credentials", e);
                throw new WebApplicationException(Response.Status.INTERNAL_SERVER_ERROR);
            }

            if (required) {
                final String challenge = String.format(CHALLENGE_FORMAT, realm);
                throw new WebApplicationException(Response.status(Response.Status.UNAUTHORIZED)
                        .header(HttpHeaders.WWW_AUTHENTICATE,
                                challenge)
                        .entity("Credentials are required to access this resource.")
                        .type(MediaType.TEXT_PLAIN_TYPE)
                        .build());
            }
            return null;
        }
    }

    private final Authenticator<JsonWebToken, T> authenticator;
    private final JsonWebTokenVerifier tokenParser;
    private final String realm;

    /**
     * Creates a new JWTAuthProvider with the given {@link Authenticator} and realm.
     *
     * @param authenticator the authenticator which will take the JWT bearer token and convert
     *                      them into instances of {@code T}
     * @param realm         the name of the authentication realm
     */
    public JWTAuthProvider(Authenticator<JsonWebToken, T> authenticator, JsonWebTokenVerifier tokenParser, String realm) {
        this.authenticator = authenticator;
        this.tokenParser = tokenParser;
        this.realm = realm;
    }

    @Override
    public ComponentScope getScope() { return ComponentScope.PerRequest; }

    @Override
    public Injectable<?> getInjectable(ComponentContext ic, Auth a, Parameter c) {
        return new JWTAuthInjectable<T>(authenticator, tokenParser, realm, a.required());
    }
}
