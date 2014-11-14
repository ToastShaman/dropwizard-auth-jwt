package com.github.toastshaman.dropwizard.auth.jwt.hmac;

import com.github.toastshaman.dropwizard.auth.jwt.exceptions.InvalidSignatureException;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebToken;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebTokenClaim;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebTokenHeader;
import com.github.toastshaman.dropwizard.auth.jwt.parser.DefaultJsonWebTokenParser;
import org.junit.Test;

import static com.github.toastshaman.dropwizard.auth.jwt.JsonWebTokenUtils.bytesOf;

public class HmacSHA512VerifierTest {

    @Test
    public void
    verifies_a_valid_signature() {
        final String encodedToken = ""
                + "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9"
                + ".eyJpc3MiOiJqb2UiLCJleHAiOm51bGx9"
                + ".JFtrDyI2ODV5I_aVfX7BnIClMqXi2SEDbRI2XTL2fV6veWICptkPi6OUJUHhSP9v_7rX8brgHJn-gbDmla_aEw";

        final byte[] key = bytesOf("SECRET");
        final JsonWebToken token = new DefaultJsonWebTokenParser().parse(encodedToken);
        final HmacSHA512Verifier verifier = new HmacSHA512Verifier(key);
        verifier.verifySignature(token);
    }

    @Test(expected = InvalidSignatureException.class)
    public void
    throws_a_signature_invalid_exception_if_the_signature_does_not_match() {
        final HmacSHA512Signer signer = new HmacSHA512Signer(bytesOf("SECRET"));
        final JsonWebToken token = JsonWebToken.builder()
                .header(JsonWebTokenHeader.HS512())
                .claim(JsonWebTokenClaim.builder().issuer("joe").build())
                .build();
        final String signedToken = signer.sign(token);
        final HmacSHA512Verifier verifier = new HmacSHA512Verifier(bytesOf("DIFFERENT_KEY"));

        verifier.verifySignature(new DefaultJsonWebTokenParser().parse(signedToken));
    }
}
