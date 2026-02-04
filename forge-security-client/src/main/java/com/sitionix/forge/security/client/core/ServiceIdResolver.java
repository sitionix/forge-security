package com.sitionix.forge.security.client.core;

import com.sitionix.forge.security.client.config.ForgeSecurityClientProperties;
import org.springframework.util.StringUtils;

import java.net.URI;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

public class ServiceIdResolver {

    private final Map<String, String> aliasToServiceId;

    public ServiceIdResolver(final ForgeSecurityClientProperties properties) {
        final Map<String, String> aliasMap = new HashMap<>();
        final Map<String, ForgeSecurityClientProperties.TargetDefinition> targets =
                properties == null ? null : properties.getTargets();
        if (targets != null) {
            targets.forEach((targetId, target) -> {
                if (target == null || !StringUtils.hasText(targetId) || !StringUtils.hasText(target.getHost())) {
                    return;
                }
                final String normalizedHost = this.normalize(this.stripPort(target.getHost()));
                if (StringUtils.hasText(normalizedHost)) {
                    aliasMap.put(normalizedHost, targetId);
                }
            });
        }
        this.aliasToServiceId = Map.copyOf(aliasMap);
    }

    public String resolveServiceId(final String host) {
        final String normalized = this.normalize(this.extractHost(host));
        if (!StringUtils.hasText(normalized)) {
            return null;
        }
        return this.aliasToServiceId.get(normalized);
    }

    private String stripPort(final String value) {
        if (!StringUtils.hasText(value)) {
            return null;
        }
        final String trimmed = value.trim();
        if (trimmed.startsWith("[")) {
            final int end = trimmed.indexOf(']');
            if (end > 0) {
                return trimmed.substring(1, end);
            }
        }
        final int colonIndex = trimmed.indexOf(':');
        if (colonIndex > 0) {
            return trimmed.substring(0, colonIndex);
        }
        return trimmed;
    }

    private String extractHost(final String value) {
        if (!StringUtils.hasText(value)) {
            return null;
        }
        final String trimmed = value.trim();
        if (trimmed.contains("://")) {
            try {
                final URI uri = URI.create(trimmed);
                if (StringUtils.hasText(uri.getHost())) {
                    return uri.getHost();
                }
            } catch (final IllegalArgumentException ignored) {
                return trimmed;
            }
        }
        return this.stripPort(trimmed);
    }

    private String normalize(final String value) {
        if (!StringUtils.hasText(value)) {
            return null;
        }
        return value.trim().toLowerCase(Locale.ROOT);
    }
}
