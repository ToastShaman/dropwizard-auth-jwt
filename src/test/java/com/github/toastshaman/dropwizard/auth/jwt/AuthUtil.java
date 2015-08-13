package com.github.toastshaman.dropwizard.auth.jwt;

import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebToken;
import com.github.toastshaman.dropwizard.auth.jwt.validator.ExpiryValidator;
import com.google.common.base.Optional;
import io.dropwizard.auth.AuthenticationException;
import io.dropwizard.auth.Authenticator;
import io.dropwizard.auth.Authorizer;
import io.dropwizard.auth.PrincipalImpl;

import java.security.Principal;
import java.util.List;

public class AuthUtil {

    public static Authenticator<JsonWebToken, Principal> getJWTAuthenticator(final List<String> validUsers) {
        return new Authenticator<JsonWebToken, Principal>() {
            @Override
            public Optional<Principal> authenticate(JsonWebToken credentials) throws AuthenticationException {
                new ExpiryValidator().validate(credentials);
                final String username = credentials.claim().subject();
                if (validUsers.contains(username)) {
                    return Optional.<Principal>of(new PrincipalImpl(username));
                }
                if ("bad-guy".equals(username)) {
                    throw new AuthenticationException("CRAP");
                }
                return Optional.absent();
            }
        };
    }

    public static Authorizer<Principal> getTestAuthorizer(final String validUser, final String validRole) {
        return new Authorizer<Principal>() {
            @Override
            public boolean authorize(Principal principal, String role) {
                return principal != null && validUser.equals(principal.getName()) && validRole.equals(role);
            }
        };
    }
}