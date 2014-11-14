package com.github.toastshaman.dropwizard.auth.jwt.hmac;

import com.github.toastshaman.dropwizard.auth.jwt.exceptions.InvalidSignatureException;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebToken;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebTokenClaim;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebTokenHeader;
import com.github.toastshaman.dropwizard.auth.jwt.parser.DefaultJsonWebTokenParser;
import org.junit.Test;

import static com.github.toastshaman.dropwizard.auth.jwt.JsonWebTokenUtils.bytesOf;
import static com.github.toastshaman.dropwizard.auth.jwt.JsonWebTokenUtils.fromBase64;

public class HmacSHA256VerifierTest {

    private final String encodedToken = ""
            + "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9"
            + ".eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
            + ".dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    private final byte[] key = fromBase64("AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow");

    @Test
    public void
    verifies_a_valid_signature() {
        final JsonWebToken token = new DefaultJsonWebTokenParser().parse(encodedToken);
        final HmacSHA256Verifier verifier = new HmacSHA256Verifier(key);
        verifier.verifySignature(token);
    }

    @Test(expected = InvalidSignatureException.class)
    public void
    throws_a_signature_invalid_exception_if_the_signature_does_not_match() {
        final HmacSHA256Signer signer = new HmacSHA256Signer(bytesOf("SECRET"));
        final JsonWebToken token = JsonWebToken.builder()
                .header(JsonWebTokenHeader.HS256())
                .claim(JsonWebTokenClaim.builder().issuer("joe").build())
                .build();
        final String signedToken = signer.sign(token);
        final HmacSHA256Verifier verifier = new HmacSHA256Verifier(bytesOf("DIFFERENT_KEY"));

        verifier.verifySignature(new DefaultJsonWebTokenParser().parse(signedToken));
    }
}
