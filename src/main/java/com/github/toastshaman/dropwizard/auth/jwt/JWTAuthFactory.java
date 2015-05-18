package com.github.toastshaman.dropwizard.auth.jwt;

import com.github.toastshaman.dropwizard.auth.jwt.exceptions.JsonWebTokenException;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebToken;
import com.google.common.base.Optional;
import io.dropwizard.auth.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.InternalServerErrorException;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;

/**
 * A Jersey provider for JWT bearer tokens.
 *
 * @param <T> the principal type
 */
public class JWTAuthFactory<T> extends AuthFactory<JsonWebToken, T> {

    private static final Logger LOGGER = LoggerFactory.getLogger(JWTAuthFactory.class);

    private final boolean required;
    private final Class<T> generatedClass;
    private final String realm;
    private String prefix = "Bearer";
    private UnauthorizedHandler unauthorizedHandler = new DefaultUnauthorizedHandler();

    private final JsonWebTokenVerifier tokenVerifier;
    private final JsonWebTokenParser tokenParser;

    @Context
    private HttpServletRequest request;

    public JWTAuthFactory(final Authenticator<JsonWebToken, T> authenticator,
                          final String realm,
                          final Class<T> generatedClass,
                          final JsonWebTokenVerifier tokenVerifier,
                          final JsonWebTokenParser tokenParser) {
        super(authenticator);
        this.required = false;
        this.realm = realm;
        this.generatedClass = generatedClass;
        this.tokenParser = tokenParser;
        this.tokenVerifier = tokenVerifier;
    }

    private JWTAuthFactory(final boolean required,
                           final Authenticator<JsonWebToken, T> authenticator,
                           final String realm,
                           final Class<T> generatedClass,
                           final JsonWebTokenVerifier tokenVerifier,
                           final JsonWebTokenParser tokenParser) {
        super(authenticator);
        this.required = required;
        this.realm = realm;
        this.generatedClass = generatedClass;
        this.tokenParser = tokenParser;
        this.tokenVerifier = tokenVerifier;
    }

    public JWTAuthFactory<T> prefix(String prefix) {
        this.prefix = prefix;
        return this;
    }

    public JWTAuthFactory<T> responseBuilder(UnauthorizedHandler unauthorizedHandler) {
        this.unauthorizedHandler = unauthorizedHandler;
        return this;
    }

    @Override
    public AuthFactory<JsonWebToken, T> clone(boolean required) {
        return new JWTAuthFactory<>(required, authenticator(), this.realm, this.generatedClass, this.tokenVerifier, this.tokenParser).prefix(prefix).responseBuilder(unauthorizedHandler);
    }

    @Override
    public void setRequest(HttpServletRequest request) {
        this.request = request;
    }

    @Override
    public T provide() {
        if (request != null) {
            final String header = request.getHeader(HttpHeaders.AUTHORIZATION);
            try {
                if (header != null) {
                    final int space = header.indexOf(' ');
                    if (space > 0) {
                        final String method = header.substring(0, space);
                        if (prefix.equalsIgnoreCase(method)) {
                            final String rawToken = header.substring(space + 1);
                            final JsonWebToken token = tokenParser.parse(rawToken);

                            tokenVerifier.verifySignature(token);

                            final Optional<T> result = authenticator().authenticate(token);
                            if (result.isPresent()) {
                                return result.get();
                            }
                        }
                    }
                }
            } catch (JsonWebTokenException e) {
                LOGGER.warn("Error decoding credentials: " + e.getMessage(), e);
            } catch (AuthenticationException e) {
                LOGGER.warn("Error authenticating credentials", e);
                throw new InternalServerErrorException();
            }
        }

        if (required) {
            throw new WebApplicationException(unauthorizedHandler.buildResponse(prefix, realm));
        }

        return null;
    }

    @Override
    public Class<T> getGeneratedClass() {
        return generatedClass;
    }
}
