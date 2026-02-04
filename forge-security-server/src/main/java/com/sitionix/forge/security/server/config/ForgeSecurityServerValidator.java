package com.sitionix.forge.security.server.config;

import jakarta.annotation.PostConstruct;
import org.springframework.util.StringUtils;

import java.util.List;
import java.util.Map;

public class ForgeSecurityServerValidator {

    private final ForgeSecurityServerProperties properties;

    public ForgeSecurityServerValidator(final ForgeSecurityServerProperties properties) {
        this.properties = properties;
    }

    @PostConstruct
    void validate() {
        this.validateDevJwt();
        this.validatePolicies();
    }

    private void validateDevJwt() {
        final ForgeSecurityServerProperties.DevJwt devConfig = this.properties.getDev();
        if (!StringUtils.hasText(devConfig.getJwtSecret())) {
            throw new IllegalStateException("forge.security.dev.jwt-secret must be configured.");
        }
        if (!StringUtils.hasText(devConfig.getIssuer())) {
            throw new IllegalStateException("forge.security.dev.issuer must be configured.");
        }
        if (devConfig.getTtlSeconds() <= 0) {
            throw new IllegalStateException("forge.security.dev.ttl-seconds must be positive.");
        }
        if (!StringUtils.hasText(this.properties.getServiceId())) {
            throw new IllegalStateException("forge.security.service-id must be configured.");
        }
    }

    private void validatePolicies() {
        final Map<String, ForgeSecurityServerProperties.Policy> policies = this.properties.getPolicies();
        if (policies == null || policies.isEmpty()) {
            return;
        }
        policies.forEach((serviceId, policy) -> {
            if (!StringUtils.hasText(serviceId)) {
                throw new IllegalStateException("forge.security.policies key must be a logical service id.");
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
                    throw new IllegalStateException("Invalid forge.security policy entry for " + serviceId + ": " + entry);
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
}
