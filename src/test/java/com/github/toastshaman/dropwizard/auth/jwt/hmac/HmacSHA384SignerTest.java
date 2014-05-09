package com.github.toastshaman.dropwizard.auth.jwt.hmac;

import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebToken;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebTokenClaim;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebTokenHeader;
import com.google.common.base.Splitter;
import org.junit.Test;

import static com.github.toastshaman.dropwizard.auth.jwt.JsonWebTokenUtils.bytesOf;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

public class HmacSHA384SignerTest {

    @Test
    public void
    calculates_a_valid_signature() {
        final HmacSHA384Signer signer = new HmacSHA384Signer(bytesOf("SECRET"));
        final JsonWebToken token = JsonWebToken.builder().header(JsonWebTokenHeader.HS384()).claim(JsonWebTokenClaim.builder().iss("joe").build()).build();
        final String signedToken = signer.sign(token);

        final String hmac = Splitter.on(".").splitToList(signedToken).get(2);

        assertThat(hmac, equalTo("bfKlisG8O9ZxGz7LPG6MHiV0AyCRL4aD5o4P03mTZcIfEuFYeZTfWQ9lG-9z_LFG"));
    }
}
