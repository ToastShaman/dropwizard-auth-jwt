package com.github.toastshaman.dropwizard.auth.jwt;

import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebToken;
import com.google.common.io.BaseEncoding;

import static com.google.common.base.Charsets.UTF_8;

public class JsonWebTokenUtils {

    public static String payloadOf(JsonWebToken token) { return token.deserialize(); }

    public static byte[] bytesOf(String input) { return input.getBytes(UTF_8); }

    public static String toBase64(byte[] signature) { return BaseEncoding.base64Url().omitPadding().encode(signature); }
}
