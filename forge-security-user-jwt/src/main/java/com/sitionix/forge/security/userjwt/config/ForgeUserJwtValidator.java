package com.sitionix.forge.security.userjwt.config;

import com.sitionix.forge.security.userjwt.client.JwksEndpoint;
import jakarta.annotation.PostConstruct;
import org.springframework.util.StringUtils;

public class ForgeUserJwtValidator {

    private final ForgeUserJwtProperties properties;

    public ForgeUserJwtValidator(final ForgeUserJwtProperties properties) {
        this.properties = properties;
    }

    @PostConstruct
    void validate() {
        if (!StringUtils.hasText(this.properties.getAuthBaseUrl())) {
            throw new IllegalStateException("forge.user-jwt.auth-base-url must be configured.");
        }
        if (!StringUtils.hasText(this.properties.getJwksPath())) {
            throw new IllegalStateException("forge.user-jwt.jwks-path must be configured.");
        }
        this.validateJwksPath();
        if (this.properties.getCacheTtlSeconds() <= 0) {
            throw new IllegalStateException("forge.user-jwt.cache-ttl-seconds must be positive.");
        }
        if (this.properties.getConnectTimeoutMs() <= 0) {
            throw new IllegalStateException("forge.user-jwt.connect-timeout-ms must be positive.");
        }
        if (this.properties.getReadTimeoutMs() <= 0) {
            throw new IllegalStateException("forge.user-jwt.read-timeout-ms must be positive.");
        }
        if (this.properties.getClockSkewSeconds() < 0) {
            throw new IllegalStateException("forge.user-jwt.clock-skew-seconds must be zero or positive.");
        }
    }

    private void validateJwksPath() {
        try {
            JwksEndpoint.fromPath(this.properties.getJwksPath());
        } catch (final IllegalArgumentException ex) {
            throw new IllegalStateException(
                    "forge.user-jwt.jwks-path must be '/.well-known/jwks.json' or '/oauth2/v1/keys'."
            );
        }
    }
}
