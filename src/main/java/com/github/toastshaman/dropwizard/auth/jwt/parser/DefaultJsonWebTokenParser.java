package com.github.toastshaman.dropwizard.auth.jwt.parser;

import com.github.toastshaman.dropwizard.auth.jwt.JsonWebTokenParser;
import com.github.toastshaman.dropwizard.auth.jwt.exceptions.MalformedJsonWebTokenException;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebToken;
import com.google.common.base.Splitter;

import java.util.List;

import static com.github.toastshaman.dropwizard.auth.jwt.JsonWebTokenUtils.fromBase64;
import static com.github.toastshaman.dropwizard.auth.jwt.JsonWebTokenUtils.fromBase64ToString;
import static com.google.common.base.Preconditions.checkArgument;
import static java.lang.String.format;
import static org.apache.commons.lang.StringUtils.isNotBlank;

public class DefaultJsonWebTokenParser implements JsonWebTokenParser {

    @Override
    public JsonWebToken parse(String token) {
        checkArgument(isNotBlank(token));

        List<String> pieces = Splitter.on(".").omitEmptyStrings().trimResults().splitToList(token);

        if (pieces.size() != 3) {
            throw new MalformedJsonWebTokenException(format("The supplied token is malformed: [%s]", token));
        }

        String jwtHeader = fromBase64ToString(pieces.get(0));
        String jwtClaim = fromBase64ToString(pieces.get(1));
        byte[] jwtSignature = fromBase64(pieces.get(2));

        return JsonWebToken.decode().header(jwtHeader).claim(jwtClaim).signature(jwtSignature).rawToken(pieces).build();
    }


}
