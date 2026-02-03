package com.sitionix.forge.security.client.config;

import jakarta.annotation.PostConstruct;
import org.springframework.core.env.Environment;
import org.springframework.util.StringUtils;

import java.util.Arrays;

public class ForgeSecurityClientValidator {

    private final ForgeSecurityClientProperties properties;
    private final Environment environment;

    public ForgeSecurityClientValidator(final ForgeSecurityClientProperties properties,
                                        final Environment environment) {
        this.properties = properties;
        this.environment = environment;
    }

    @PostConstruct
    void validate() {
        if (!this.properties.getClient().isEnabled()) {
            return;
        }
        final ForgeSecurityMode mode = this.properties.getMode();
        final boolean isProd = Arrays.stream(this.environment.getActiveProfiles())
                .anyMatch(profile -> "prod".equalsIgnoreCase(profile));
        final boolean isItProfile = Arrays.stream(this.environment.getActiveProfiles())
                .anyMatch(profile -> "it".equalsIgnoreCase(profile));
        if (isProd && mode != ForgeSecurityMode.MTLS) {
            throw new IllegalStateException("forge.security.mode must be mtls in prod.");
        }
        if (isProd && StringUtils.hasText(this.properties.getDev().getJwtSecret())) {
            throw new IllegalStateException("forge.security.dev.jwt-secret must not be set in prod.");
        }
        if (mode == null) {
            throw new IllegalStateException("forge.security.mode must be configured.");
        }
        this.validateStaticToken(isProd, isItProfile, mode);
        if (mode == ForgeSecurityMode.DEV_JWT) {
            this.validateDevJwt();
        }
    }

    private void validateDevJwt() {
        final ForgeSecurityClientProperties.DevJwt devConfig = this.properties.getDev();
        if (StringUtils.hasText(devConfig.getStaticToken())) {
            return;
        }
        if (!StringUtils.hasText(devConfig.getJwtSecret())) {
            throw new IllegalStateException("forge.security.dev.jwt-secret must be configured for dev-jwt.");
        }
        if (!StringUtils.hasText(devConfig.getIssuer())) {
            throw new IllegalStateException("forge.security.dev.issuer must be configured for dev-jwt.");
        }
        if (devConfig.getTtlSeconds() <= 0) {
            throw new IllegalStateException("forge.security.dev.ttl-seconds must be positive for dev-jwt.");
        }
        if (!StringUtils.hasText(this.properties.getServiceName())) {
            throw new IllegalStateException("forge.security.service-name must be configured for dev-jwt.");
        }
    }

    private void validateStaticToken(final boolean isProd,
                                     final boolean isItProfile,
                                     final ForgeSecurityMode mode) {
        final ForgeSecurityClientProperties.DevJwt devConfig = this.properties.getDev();
        if (!StringUtils.hasText(devConfig.getStaticToken())) {
            return;
        }
        if (mode != ForgeSecurityMode.DEV_JWT) {
            throw new IllegalStateException("forge.security.dev.static-token requires dev-jwt mode.");
        }
        if (isProd) {
            throw new IllegalStateException("forge.security.dev.static-token must not be set in prod.");
        }
        if (!isItProfile) {
            throw new IllegalStateException("forge.security.dev.static-token is allowed only in it profile.");
        }
    }
}
