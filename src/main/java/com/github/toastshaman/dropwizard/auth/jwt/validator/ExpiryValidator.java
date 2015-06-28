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

    public ExpiryValidator(Duration skew) {
        this.acceptableClockSkew = skew;
    }

    public ExpiryValidator() {
        this.acceptableClockSkew = Duration.standardMinutes(2);
    }

    @Override
    public void validate(JsonWebToken token) {
        if (token.claim() != null) {
            final Instant now = new Instant();
            final Instant issuedAt = fromNullable(toInstant(token.claim().issuedAt())).or(now);
            final Instant expiration = fromNullable(toInstant(token.claim().expiration())).or(new Instant(Long.MAX_VALUE));
            final Instant notBefore = fromNullable(toInstant(token.claim().notBefore())).or(now);

            if (issuedAt.isAfter(expiration) || notBefore.isAfterNow() || !inInterval(issuedAt, expiration, now)) {
                throw new TokenExpiredException();
            }
        }
    }

    private boolean inInterval(Instant start, Instant end, Instant now) {
        final Interval interval = new Interval(start, end);
        final Interval currentTimeWithSkew = new Interval(now.minus(acceptableClockSkew), now.plus(acceptableClockSkew));
        return interval.overlaps(currentTimeWithSkew);
    }

    private Instant toInstant(Long input) {
        if (input == null) {
            return null;
        }
        return new Instant(input * 1000);
    }
}
