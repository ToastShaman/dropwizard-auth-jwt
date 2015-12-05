package com.github.toastshaman.dropwizard.auth.jwt.example;

import com.github.toastshaman.dropwizard.auth.jwt.JWTAuthFilter;
import com.github.toastshaman.dropwizard.auth.jwt.JsonWebTokenParser;
import com.github.toastshaman.dropwizard.auth.jwt.JsonWebTokenValidator;
import com.github.toastshaman.dropwizard.auth.jwt.hmac.HmacSHA512Verifier;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebToken;
import com.github.toastshaman.dropwizard.auth.jwt.parser.DefaultJsonWebTokenParser;
import com.github.toastshaman.dropwizard.auth.jwt.validator.ExpiryValidator;
import com.google.common.base.Optional;
import io.dropwizard.Application;
import io.dropwizard.auth.AuthDynamicFeature;
import io.dropwizard.auth.AuthValueFactoryProvider;
import io.dropwizard.auth.Authenticator;
import io.dropwizard.setup.Bootstrap;
import io.dropwizard.setup.Environment;
import org.glassfish.jersey.server.filter.RolesAllowedDynamicFeature;

import java.security.Principal;

/**
 * A sample dropwizard application that shows how to set up the JWT Authentication provider.
 * <p/>
 * The Authentication Provider will parse the tokens supplied in the "Authorization" HTTP header in each HTTP request
 * given your resource is protected with the @Auth annotation.
 */
public class JwtAuthApplication extends Application<MyConfiguration> {

    @Override
    public void initialize(Bootstrap<MyConfiguration> configurationBootstrap) {
    }

    @Override
    public void run(MyConfiguration configuration, Environment environment) throws Exception {
        final JsonWebTokenParser tokenParser = new DefaultJsonWebTokenParser();
        final HmacSHA512Verifier tokenVerifier = new HmacSHA512Verifier(configuration.getJwtTokenSecret());
        environment.jersey().register(new AuthDynamicFeature(
                new JWTAuthFilter.Builder<>()
                        .setTokenParser(tokenParser)
                        .setTokenVerifier(tokenVerifier)
                        .setRealm("realm")
                        .setPrefix("Bearer")
                        .setAuthenticator(new JwtAuthApplication.ExampleAuthenticator())
                        .buildAuthFilter()));
        environment.jersey().register(new AuthValueFactoryProvider.Binder<>(Principal.class));
        environment.jersey().register(RolesAllowedDynamicFeature.class);
        environment.jersey().register(new SecuredResource(configuration.getJwtTokenSecret()));
    }

    private static class ExampleAuthenticator implements Authenticator<JsonWebToken, Principal> {
        @Override
        public Optional<Principal> authenticate(JsonWebToken token) {
            final JsonWebTokenValidator expiryValidator = new ExpiryValidator();

            // Provide your own implementation to lookup users based on the principal attribute in the
            // JWT Token. E.g.: lookup users from a database etc.
            // This method will be called once the token's signature has been verified

            // In case you want to verify different parts of the token you can do that here.
            // E.g.: Verifying that the provided token has not expired.

            // All JsonWebTokenExceptions will result in a 401 Unauthorized response.

            expiryValidator.validate(token);

            if ("good-guy".equals(token.claim().subject())) {
                final Principal principal = new Principal() {
                    @Override
                    public String getName() {
                        return "good-guy";
                    }
                };
                return Optional.of(principal);
            }

            return Optional.absent();
        }
    }

    public static void main(String[] args) throws Exception {
        new JwtAuthApplication().run("server");
    }
}
