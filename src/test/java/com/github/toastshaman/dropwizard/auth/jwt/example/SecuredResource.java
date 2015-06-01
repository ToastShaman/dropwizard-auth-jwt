package com.github.toastshaman.dropwizard.auth.jwt.example;

import com.github.toastshaman.dropwizard.auth.jwt.hmac.HmacSHA512Signer;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebToken;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebTokenClaim;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebTokenHeader;
import io.dropwizard.auth.Auth;
import org.joda.time.DateTime;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import java.util.Map;

import static java.util.Collections.singletonMap;
import static javax.ws.rs.core.MediaType.APPLICATION_JSON;

@Path("/jwt")
@Produces(APPLICATION_JSON)
public class SecuredResource {

    private final byte[] tokenSecret;

    public SecuredResource(byte[] tokenSecret) {
        this.tokenSecret = tokenSecret;
    }

    @GET
    @Path("/generate-token")
    public Map<String, String> generate() {
        final HmacSHA512Signer signer = new HmacSHA512Signer(tokenSecret);
        final JsonWebToken token = JsonWebToken.builder()
                .header(JsonWebTokenHeader.HS512())
                .claim(JsonWebTokenClaim.builder()
                        .subject("good-guy")
                        .issuedAt(new DateTime().plusHours(1))
                        .build())
                .build();
        final String signedToken = signer.sign(token);
        return singletonMap("token", signedToken);
    }

    @GET
    @Path("/check-token")
    public Map<String, String> get(@Auth User user) {
        return singletonMap("username", user.getUsername());
    }
}
