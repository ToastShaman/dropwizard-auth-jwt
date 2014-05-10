package com.github.toastshaman.dropwizard.auth.jwt.validator;

import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebToken;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebTokenClaim;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebTokenHeader;
import org.joda.time.DateTime;
import org.junit.Test;

public class ExpiryValidatorTest {

    @Test public void
    passes_validation_for_non_expired_token() {

        JsonWebToken token = JsonWebToken.builder()
                .header(JsonWebTokenHeader.HS256())
                .claim(
                        JsonWebTokenClaim.builder()
                                .iat(DateTime.now().minusDays(1))
                                .exp(DateTime.now().plusDays(1))
                                .build()
                )
                .build();

        ExpiryValidator validator = new ExpiryValidator();

        validator.validate(token);
    }

    @Test public void
    passes_validation_for_token_without_any_time_constraints() {

        JsonWebToken token = JsonWebToken.builder()
                .header(JsonWebTokenHeader.HS256())
                .claim(JsonWebTokenClaim.builder().build())
                .build();

        ExpiryValidator validator = new ExpiryValidator();

        validator.validate(token);
    }
}
