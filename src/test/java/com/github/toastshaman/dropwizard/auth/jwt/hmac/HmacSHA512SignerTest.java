package com.github.toastshaman.dropwizard.auth.jwt.hmac;

import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebToken;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebTokenClaims;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebTokenHeader;
import com.google.common.base.Splitter;
import org.junit.Test;

import static com.github.toastshaman.dropwizard.auth.jwt.JsonWebTokenUtils.bytesOf;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

public class HmacSHA512SignerTest {

    @Test
    public void
    calculates_a_valid_signature() {
        final HmacSHA512Signer signer = new HmacSHA512Signer(bytesOf("SECRET"));
        final JsonWebToken token = JsonWebToken.builder().header(JsonWebTokenHeader.HS512()).claim(JsonWebTokenClaims.builder().iss("joe").build()).build();
        final String signedToken = signer.sign(token);

        final String hmac = Splitter.on(".").splitToList(signedToken).get(2);

        assertThat(hmac, equalTo("JFtrDyI2ODV5I_aVfX7BnIClMqXi2SEDbRI2XTL2fV6veWICptkPi6OUJUHhSP9v_7rX8brgHJn-gbDmla_aEw"));
    }
}
