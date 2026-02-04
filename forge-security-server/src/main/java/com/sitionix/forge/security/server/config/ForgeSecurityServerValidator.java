package com.sitionix.forge.security.server.config;

import jakarta.annotation.PostConstruct;
import org.springframework.core.env.Environment;
import org.springframework.util.StringUtils;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

public class ForgeSecurityServerValidator {

    private final ForgeSecurityServerProperties properties;
    private final Environment environment;

    public ForgeSecurityServerValidator(final ForgeSecurityServerProperties properties,
                                        final Environment environment) {
        this.properties = properties;
        this.environment = environment;
    }

    @PostConstruct
    void validate() {
        if (!this.properties.getServer().isEnabled()) {
            return;
        }
        final ForgeSecurityMode mode = this.properties.getMode();
        final boolean isProd = Arrays.stream(this.environment.getActiveProfiles())
                .anyMatch(profile -> "prod".equalsIgnoreCase(profile));
        if (isProd && mode != ForgeSecurityMode.MTLS) {
            throw new IllegalStateException("forge.security.mode must be mtls in prod.");
        }
        if (isProd && StringUtils.hasText(this.properties.getDev().getJwtSecret())) {
            throw new IllegalStateException("forge.security.dev.jwt-secret must not be set in prod.");
        }
        if (mode == null) {
            throw new IllegalStateException("forge.security.mode must be configured.");
        }
        this.validateServiceIds();
        this.validateAcceptedAudiences();
        this.validatePolicies();
        if (mode == ForgeSecurityMode.DEV_JWT) {
            this.validateDevJwt();
        }
    }

    private void validateDevJwt() {
        final ForgeSecurityServerProperties.DevJwt devConfig = this.properties.getDev();
        if (!StringUtils.hasText(devConfig.getJwtSecret())) {
            throw new IllegalStateException("forge.security.dev.jwt-secret must be configured for dev-jwt.");
        }
        if (!StringUtils.hasText(devConfig.getIssuer())) {
            throw new IllegalStateException("forge.security.dev.issuer must be configured for dev-jwt.");
        }
        if (devConfig.getTtlSeconds() <= 0) {
            throw new IllegalStateException("forge.security.dev.ttl-seconds must be positive for dev-jwt.");
        }
        if (!StringUtils.hasText(this.properties.getServiceId())) {
            throw new IllegalStateException("forge.security.service-id must be configured for dev-jwt.");
        }
    }

    private void validatePolicies() {
        final Map<String, ForgeSecurityServerProperties.Policy> policies = this.properties.getPolicies();
        if (policies == null || policies.isEmpty()) {
            return;
        }
        final List<String> serviceIds = this.getServiceIds();
        policies.forEach((serviceName, policy) -> {
            if (!this.isLogicalServiceId(serviceName, serviceIds)) {
                throw new IllegalStateException("forge.security.policies key must be a logical service id: " + serviceName);
            }
            if (policy == null || policy.getAllow() == null || policy.getAllow().isEmpty()) {
                return;
            }
            final boolean allowAll = policy.getAllow().stream()
                    .filter(StringUtils::hasText)
                    .map(String::trim)
                    .anyMatch("*"::equals);
            if (allowAll) {
                return;
            }
            for (final String entry : policy.getAllow()) {
                if (!this.isValidPolicyEntry(entry)) {
                    throw new IllegalStateException("Invalid forge.security policy entry for " + serviceName + ": " + entry);
                }
            }
        });
    }

    private boolean isValidPolicyEntry(final String entry) {
        if (!StringUtils.hasText(entry)) {
            return false;
        }
        final String trimmed = entry.trim();
        if ("*".equals(trimmed)) {
            return true;
        }
        final String normalized = this.stripScope(trimmed);
        final String method = this.extractMethod(normalized);
        if (method == null) {
            return false;
        }
        final String path = normalized.substring(method.length()).trim();
        return StringUtils.hasText(path) && path.startsWith("/");
    }

    private String stripScope(final String entry) {
        final int scopeIndex = entry.indexOf(':');
        if (scopeIndex > 0) {
            return entry.substring(0, scopeIndex).trim();
        }
        return entry;
    }

    private String extractMethod(final String entry) {
        final String upper = entry.trim().toUpperCase();
        for (final String method : List.of("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS")) {
            if (upper.startsWith(method + " ")) {
                return method;
            }
        }
        return null;
    }

    private void validateServiceIds() {
        if (!StringUtils.hasText(this.properties.getServiceId())) {
            throw new IllegalStateException("forge.security.service-id must be configured.");
        }
        final List<String> serviceIds = this.getServiceIds();
        if (serviceIds.isEmpty()) {
            throw new IllegalStateException("forge.security.services must be configured.");
        }
        if (!this.isLogicalServiceId(this.properties.getServiceId(), serviceIds)) {
            throw new IllegalStateException("forge.security.service-id must be listed in forge.security.services.");
        }
    }

    private void validateAcceptedAudiences() {
        final List<String> serviceIds = this.getServiceIds();
        final List<String> acceptedAudiences = this.properties.getAcceptedAudiences();
        if (acceptedAudiences == null || acceptedAudiences.isEmpty()) {
            return;
        }
        for (final String audience : acceptedAudiences) {
            if ("*".equals(StringUtils.trimWhitespace(audience))) {
                throw new IllegalStateException("forge.security.accepted-audiences must not contain '*'.");
            }
            if (!this.isLogicalServiceId(audience, serviceIds)) {
                throw new IllegalStateException("forge.security.accepted-audiences must contain logical service ids only.");
            }
        }
    }

    private List<String> getServiceIds() {
        if (this.properties.getServices() == null || this.properties.getServices().isEmpty()) {
            return List.of();
        }
        return this.properties.getServices().values().stream()
                .filter(service -> service != null && StringUtils.hasText(service.getId()))
                .map(service -> normalize(service.getId()))
                .distinct()
                .toList();
    }

    private boolean isLogicalServiceId(final String value, final List<String> serviceIds) {
        if (!StringUtils.hasText(value)) {
            return false;
        }
        return serviceIds.contains(normalize(value));
    }

    private static String normalize(final String value) {
        return value.trim().toLowerCase();
    }
}
