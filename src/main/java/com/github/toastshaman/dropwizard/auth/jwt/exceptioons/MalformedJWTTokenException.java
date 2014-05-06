package com.github.toastshaman.dropwizard.auth.jwt.exceptioons;

public class MalformedJWTTokenException extends RuntimeException {

    public MalformedJWTTokenException(String msg) { super(msg); }

    public MalformedJWTTokenException(String msg, Throwable t) { super(msg, t); }
}
