package com.github.toastshaman.dropwizard.auth.jwt.exceptioons;

public class JsonWebTokenException extends RuntimeException {

    public JsonWebTokenException(String msg, Throwable t) { super(msg, t); }
}
