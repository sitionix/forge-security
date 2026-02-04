package com.sitionix.forge.security.client.config;

import jakarta.annotation.PostConstruct;
import org.springframework.util.StringUtils;

import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

public class ForgeSecurityClientValidator {

    private final ForgeSecurityClientProperties properties;

    public ForgeSecurityClientValidator(final ForgeSecurityClientProperties properties) {
        this.properties = properties;
    }

    @PostConstruct
    void validate() {
        this.validateDevJwt();
        this.validateTargets();
    }

    private void validateDevJwt() {
        final ForgeSecurityClientProperties.DevJwt devConfig = this.properties.getDev();
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

    private void validateTargets() {
        final Map<String, ForgeSecurityClientProperties.TargetDefinition> targets = this.properties.getTargets();
        if (targets == null || targets.isEmpty()) {
            throw new IllegalStateException("forge.security.targets must be configured.");
        }
        final Set<String> hosts = new HashSet<>();
        for (final Map.Entry<String, ForgeSecurityClientProperties.TargetDefinition> entry : targets.entrySet()) {
            final String targetId = entry.getKey();
            if (!StringUtils.hasText(targetId)) {
                throw new IllegalStateException("forge.security.targets key must be a logical service id.");
            }
            final ForgeSecurityClientProperties.TargetDefinition target = entry.getValue();
            if (target == null || !StringUtils.hasText(target.getHost())) {
                throw new IllegalStateException("forge.security.targets." + targetId + ".host must be configured.");
            }
            final String normalizedHost = target.getHost().trim().toLowerCase(Locale.ROOT);
            if (!hosts.add(normalizedHost)) {
                throw new IllegalStateException("forge.security.targets host must be unique: " + target.getHost());
            }
        }
    }
}
