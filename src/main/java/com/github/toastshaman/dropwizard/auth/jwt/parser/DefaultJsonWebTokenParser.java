package com.github.toastshaman.dropwizard.auth.jwt.parser;

import com.github.toastshaman.dropwizard.auth.jwt.JsonWebTokenParser;
import com.github.toastshaman.dropwizard.auth.jwt.exceptioons.MalformedJsonWebTokenException;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebToken;
import com.google.common.base.Splitter;
import com.google.common.io.BaseEncoding;

import java.nio.charset.Charset;
import java.util.List;

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

        String jwtHeader = decodeAsString(pieces.get(0));
        String jwtClaim = decodeAsString(pieces.get(1));
        byte[] jwtSignature = decode(pieces.get(2));

        return JsonWebToken.decode().header(jwtHeader).claim(jwtClaim).signature(jwtSignature).rawToken(pieces).build();
    }

    private String decodeAsString(String input) { return new String(decode(input), Charset.forName("UTF-8")); }

    private byte[] decode(String input) { return BaseEncoding.base64Url().omitPadding().decode(input); }
}
