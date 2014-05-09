package com.github.toastshaman.dropwizard.auth.jwt.validator;

import com.github.toastshaman.dropwizard.auth.jwt.JsonWebTokenValidator;
import com.github.toastshaman.dropwizard.auth.jwt.exceptions.TokenExpiredException;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebToken;
import org.joda.time.Duration;
import org.joda.time.Instant;
import org.joda.time.Interval;

import static com.google.common.base.Optional.fromNullable;

public class ExpiryValidator implements JsonWebTokenValidator {

    private final Duration acceptableClockSkew;

    public ExpiryValidator(Duration skew) { this.acceptableClockSkew = skew; }

    public ExpiryValidator() { this.acceptableClockSkew = Duration.standardMinutes(2); }

    @Override
    public void validate(JsonWebToken token) {
        if (token.claim() != null) {
            Instant issuedAt = new Instant(fromNullable(token.claim().iat()).or(0L));
            Instant expiration = new Instant(fromNullable(token.claim().exp()).or(Long.MAX_VALUE));

            if (issuedAt.isAfter(expiration) || !inInterval(issuedAt, expiration)) {
                throw new TokenExpiredException();
            }
        }
    }

    private boolean inInterval(Instant start, Instant end) {
        Interval interval = new Interval(start, end);
        Instant now = now();
        Interval currentTimeWithSkew = new Interval(now.minus(acceptableClockSkew), now.plus(acceptableClockSkew));
        return interval.overlaps(currentTimeWithSkew);
    }

    private Instant now() { return new Instant(); }
}
