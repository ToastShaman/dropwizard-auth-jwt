package com.github.toastshaman.dropwizard.auth.jwt;

/**
 * Utility class containing the supported HMAC algorithms.
 * <p>
 * See Appendix A in the Java <a href="https://docs.oracle.com/javase/7/docs/technotes/guides/security/crypto/CryptoSpec.html#AppA">Cryptography
 * Architecture Reference Guide</a>
 */
public class JsonWebTokenAlgorithms {

    public static final String HS256 = "HS256";

    public static final String HS384 = "HS384";

    public static final String HS512 = "HS512";
}
