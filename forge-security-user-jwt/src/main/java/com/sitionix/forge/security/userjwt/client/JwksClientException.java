package com.sitionix.forge.security.userjwt.client;

public class JwksClientException extends RuntimeException {

    public JwksClientException(final String message) {
        super(message);
    }

    public JwksClientException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
