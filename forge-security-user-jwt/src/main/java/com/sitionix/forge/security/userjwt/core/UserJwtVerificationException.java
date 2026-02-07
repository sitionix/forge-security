package com.sitionix.forge.security.userjwt.core;

public class UserJwtVerificationException extends RuntimeException {

    public UserJwtVerificationException(final String message) {
        super(message);
    }

    public UserJwtVerificationException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
