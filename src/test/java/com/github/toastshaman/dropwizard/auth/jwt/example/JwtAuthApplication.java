package com.github.toastshaman.dropwizard.auth.jwt.example;

import com.github.toastshaman.dropwizard.auth.jwt.JWTAuthFactory;
import com.github.toastshaman.dropwizard.auth.jwt.JsonWebTokenParser;
import com.github.toastshaman.dropwizard.auth.jwt.JsonWebTokenValidator;
import com.github.toastshaman.dropwizard.auth.jwt.exceptions.TokenExpiredException;
import com.github.toastshaman.dropwizard.auth.jwt.hmac.HmacSHA512Verifier;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebToken;
import com.github.toastshaman.dropwizard.auth.jwt.parser.DefaultJsonWebTokenParser;
import com.github.toastshaman.dropwizard.auth.jwt.validator.ExpiryValidator;
import com.google.common.base.Optional;
import io.dropwizard.Application;
import io.dropwizard.auth.AuthFactory;
import io.dropwizard.auth.AuthenticationException;
import io.dropwizard.auth.Authenticator;
import io.dropwizard.setup.Bootstrap;
import io.dropwizard.setup.Environment;

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
        environment.jersey().register(AuthFactory.binder(new JWTAuthFactory<>(new ExampleAuthenticator(), "realm", User.class, tokenVerifier, tokenParser)));
        environment.jersey().register(new SecuredResource(configuration.getJwtTokenSecret()));
    }

    private static class ExampleAuthenticator implements Authenticator<JsonWebToken, User> {
        @Override
        public Optional<User> authenticate(JsonWebToken token) throws AuthenticationException {
            final JsonWebTokenValidator expiryValidator = new ExpiryValidator();

            // Provide your own implementation to lookup users based on the principal attribute in the
            // JWT Token. E.g.: lookup users from a database etc.
            // This method will be called once the token's signature has been verified

            // In case you want to verify different parts of the token you can do that here.
            // E.g.: Verifying that the provided token has not expired.
            try {
                expiryValidator.validate(token);
            } catch (TokenExpiredException e) {
                throw new AuthenticationException(e.getMessage(), e);
            }

            if ("good-guy".equals(token.claim().subject())) {
                return Optional.of(new User("good-guy"));
            }

            return Optional.absent();
        }
    }

    public static void main(String[] args) throws Exception {
        // new JwtAuthApplication().run(args);
        new JwtAuthApplication().run(new String[]{"server"});
    }
}
