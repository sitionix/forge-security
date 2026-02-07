package com.sitionix.forge.security.userjwt.client;

import org.springframework.util.StringUtils;

public enum JwksEndpoint {

    CANONICAL("/.well-known/jwks.json"),
    ALIAS("/oauth2/v1/keys");

    private final String path;

    JwksEndpoint(final String path) {
        this.path = path;
    }

    public String getPath() {
        return this.path;
    }

    public static JwksEndpoint fromPath(final String configuredPath) {
        if (!StringUtils.hasText(configuredPath)) {
            return CANONICAL;
        }
        final String normalized = normalizePath(configuredPath);
        for (final JwksEndpoint endpoint : values()) {
            if (endpoint.path.equals(normalized)) {
                return endpoint;
            }
        }
        throw new IllegalArgumentException("Unsupported jwksPath: " + configuredPath);
    }

    public static String normalizePath(final String configuredPath) {
        String normalized = configuredPath.trim();
        while (normalized.endsWith("/")) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }
        if (!normalized.startsWith("/")) {
            normalized = "/" + normalized;
        }
        return normalized;
    }
}
