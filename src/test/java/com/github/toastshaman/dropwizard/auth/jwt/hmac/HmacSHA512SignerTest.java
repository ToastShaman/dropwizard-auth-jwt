package com.github.toastshaman.dropwizard.auth.jwt.hmac;

import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebToken;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebTokenClaim;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebTokenHeader;
import com.google.common.base.Splitter;
import org.junit.Test;

import static com.github.toastshaman.dropwizard.auth.jwt.JsonWebTokenUtils.bytesOf;
import static org.assertj.core.api.Assertions.assertThat;

public class HmacSHA512SignerTest {

    @Test
    public void
    calculates_a_valid_signature() {
        final HmacSHA512Signer signer = new HmacSHA512Signer(bytesOf("SECRET"));
        final JsonWebToken token = JsonWebToken.builder()
                .header(JsonWebTokenHeader.HS512())
                .claim(JsonWebTokenClaim.builder().issuer("joe").build())
                .build();
        final String signedToken = signer.sign(token);

        final String hmac = Splitter.on(".").splitToList(signedToken).get(2);

        assertThat(hmac).isEqualTo("bMndBygjDjxbLzWF672Qa1SYU3973uSWxqyyW0epnE_zviu8VZ5tKt9u3USWAsDeUJ6gx3TceRF9t_FRFg2j5w");
    }
}
