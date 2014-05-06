package com.github.toastshaman.dropwizard.auth.jwt.exceptioons;

public class JWTTokenException extends RuntimeException {

    public JWTTokenException(String msg, Throwable t) { super(msg, t); }
}
