package com.github.toastshaman.dropwizard.auth.jwt.model;

import com.github.toastshaman.dropwizard.auth.jwt.hmac.HmacSHA256Signer;
import com.github.toastshaman.dropwizard.auth.jwt.parser.DefaultJsonWebTokenParser;
import org.joda.time.DateTime;
import org.junit.Test;

import static com.github.toastshaman.dropwizard.auth.jwt.JsonWebTokenUtils.fromBase64;
import static org.assertj.core.api.Assertions.assertThat;

public class JsonWebTokenTest {

    @Test
    public void builds_a_valid_token() {

        final String expected = ""
            + "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9"
            + ".eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
            + ".lliDzOlRAdGUCfCHCPx_uisb6ZfZ1LRQa0OJLeYTTpY";

        final byte[] key = fromBase64("AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow");

        final JsonWebToken token = JsonWebToken.builder()
            .header(JsonWebTokenHeader.HS256())
            .claim(JsonWebTokenClaim.builder()
                .issuer("joe")
                .expiration(DateTime.now().withMillis(1300819380000L))
                .param("http://example.com/is_root", true)
                .build()
            ).build();

        final String encodedToken = new HmacSHA256Signer(key).sign(token);

        assertThat(encodedToken).isEqualTo(expected);
    }

    @Test
    public void builds_a_valid_token_with_all_claim_fields() {
        final String expected = ""
            + "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9"
            + ".eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImlhdCI6MTMwMDgxOTMyMCwibmJmIjoxMzAwODE5MzIxLCJzdWIiOiJzdWIiLCJodHRwOi8vZXhhbXBsZS5jb20vaXNfcm9vdCI6dHJ1ZX0"
            + ".H20YqViCitX1Hb_iOP2sqCMMg3oan6KNNd-9gpzjUYI";

        final byte[] key = fromBase64("AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow");

        final JsonWebToken token = JsonWebToken.builder()
            .header(JsonWebTokenHeader.HS256())
            .claim(JsonWebTokenClaim.builder()
                .issuer("joe")
                .subject("sub")
                .expiration(DateTime.now().withMillis(1300819380000L))
                .issuedAt(DateTime.now().withMillis(1300819320000L))
                .notBefore(DateTime.now().withMillis(1300819321000L))
                .param("http://example.com/is_root", true)
                .build()
            ).build();

        final String encodedToken = new HmacSHA256Signer(key).sign(token);

        assertThat(encodedToken).isEqualTo(expected);
    }

    @Test
    public void tokens_built_from_strings_have_the_same_hashCode_and_are_equal() {
        final String token = ""
            + "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9"
            + ".eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImlhdCI6MTMwMDgxOTMyMCwibmJmIjoxMzAwODE5MzIxLCJzdWIiOiJzdWIiLCJodHRwOi8vZXhhbXBsZS5jb20vaXNfcm9vdCI6dHJ1ZX0"
            + ".H20YqViCitX1Hb_iOP2sqCMMg3oan6KNNd-9gpzjUYI";

        final JsonWebToken tokenOne = new DefaultJsonWebTokenParser().parse(token);
        final JsonWebToken tokenTwo = new DefaultJsonWebTokenParser().parse(token);

        assertThat(tokenOne).isEqualTo(tokenTwo);
        assertThat(tokenOne.hashCode()).isEqualTo(tokenTwo.hashCode());
    }

    @Test
    public void tokens_with_different_signatures_have_not_the_same_hashCode_and_are_not_equal() {
        final String token = ""
            + "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9"
            + ".eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImlhdCI6MTMwMDgxOTMyMCwibmJmIjoxMzAwODE5MzIxLCJzdWIiOiJzdWIiLCJodHRwOi8vZXhhbXBsZS5jb20vaXNfcm9vdCI6dHJ1ZX0"
            + ".H20YqViCitX1Hb_iOP2sqCMMg3oan6KNNd-9gpzjUYI";

        final String tokenWithDifferentSignature = ""
            + "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9"
            + ".eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImlhdCI6MTMwMDgxOTMyMCwibmJmIjoxMzAwODE5MzIxLCJzdWIiOiJzdWIiLCJodHRwOi8vZXhhbXBsZS5jb20vaXNfcm9vdCI6dHJ1ZX0"
            + ".H20YqViCitX1Hb_iOP2sqCMMg3oan6KNNd-9gpzjUYIBOO";

        final JsonWebToken tokenOne = new DefaultJsonWebTokenParser().parse(token);
        final JsonWebToken tokenTwo = new DefaultJsonWebTokenParser().parse(tokenWithDifferentSignature);

        assertThat(tokenOne).isNotEqualTo(tokenTwo);
        assertThat(tokenOne.hashCode()).isNotEqualTo(tokenTwo.hashCode());
    }

    @Test
    public void identical_tokens_have_the_same_hashCode_and_are_equal() {
        final JsonWebToken tokenOne = JsonWebToken.builder()
            .header(JsonWebTokenHeader.HS256())
            .claim(JsonWebTokenClaim.builder()
                .issuer("joe")
                .subject("sub")
                .expiration(DateTime.now().withMillis(1300819380000L))
                .issuedAt(DateTime.now().withMillis(1300819320000L))
                .notBefore(DateTime.now().withMillis(1300819321000L))
                .param("http://example.com/is_root", true)
                .build()
            ).build();

        final JsonWebToken tokenTwo = JsonWebToken.builder()
            .header(JsonWebTokenHeader.HS256())
            .claim(JsonWebTokenClaim.builder()
                .issuer("joe")
                .subject("sub")
                .expiration(DateTime.now().withMillis(1300819380000L))
                .issuedAt(DateTime.now().withMillis(1300819320000L))
                .notBefore(DateTime.now().withMillis(1300819321000L))
                .param("http://example.com/is_root", true)
                .build()
            ).build();

        assertThat(tokenOne).isEqualTo(tokenTwo);
        assertThat(tokenOne.hashCode()).isEqualTo(tokenTwo.hashCode());
    }

    @Test
    public void nonidentical_tokens_have_not_the_same_hashCode_and_are_not_equal() {
        final JsonWebToken tokenOne = JsonWebToken.builder()
            .header(JsonWebTokenHeader.HS256())
            .claim(JsonWebTokenClaim.builder()
                .issuer("joe")
                .subject("sub")
                .expiration(DateTime.now().withMillis(1300819380000L))
                .issuedAt(DateTime.now().withMillis(1300819320000L))
                .notBefore(DateTime.now().withMillis(1300819321000L))
                .param("http://example.com/is_root", true)
                .build()
            ).build();

        final JsonWebToken tokenTwo = JsonWebToken.builder()
            .header(JsonWebTokenHeader.HS256())
            .claim(JsonWebTokenClaim.builder()
                .issuer("joe")
                .subject("DIFFERENT SUBJECT")
                .expiration(DateTime.now().withMillis(1300819380000L))
                .issuedAt(DateTime.now().withMillis(1300819320000L))
                .notBefore(DateTime.now().withMillis(1300819321000L))
                .param("http://example.com/is_root", true)
                .build()
            ).build();

        assertThat(tokenOne).isNotEqualTo(tokenTwo);
        assertThat(tokenOne.hashCode()).isNotEqualTo(tokenTwo.hashCode());
    }
}
