package com.github.toastshaman.dropwizard.auth.jwt.hmac;

import com.github.toastshaman.dropwizard.auth.jwt.exceptions.InvalidSignatureException;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebToken;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebTokenClaim;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebTokenHeader;
import com.github.toastshaman.dropwizard.auth.jwt.parser.DefaultJsonWebTokenParser;
import org.junit.Test;

import static com.github.toastshaman.dropwizard.auth.jwt.JsonWebTokenUtils.bytesOf;

public class HmacSHA384VerifierTest {

    @Test
    public void
    verifies_a_valid_signature() {
        final String encodedToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzM4NCJ9"
                + ".eyJpc3MiOiJqb2UiLCJleHAiOm51bGx9"
                + ".yS0gHKcZXzOd5rR1v9g7WMOyv-TML_eDwxY_pk2NBvivoYk3YibsRk_zL9YUauJI";

        final byte[] key = bytesOf("SECRET");
        final JsonWebToken token = new DefaultJsonWebTokenParser().parse(encodedToken);
        final HmacSHA384Verifier verifier = new HmacSHA384Verifier(key);
        verifier.verifySignature(token);
    }

    @Test(expected = InvalidSignatureException.class)
    public void
    throws_a_signature_invalid_exception_if_the_signature_does_not_match() {
        final HmacSHA384Signer signer = new HmacSHA384Signer(bytesOf("SECRET"));
        final JsonWebToken token = JsonWebToken.builder()
                .header(JsonWebTokenHeader.HS384())
                .claim(JsonWebTokenClaim.builder().issuer("joe").build())
                .build();
        final String signedToken = signer.sign(token);
        final HmacSHA384Verifier verifier = new HmacSHA384Verifier(bytesOf("DIFFERENT_KEY"));

        verifier.verifySignature(new DefaultJsonWebTokenParser().parse(signedToken));
    }
}
