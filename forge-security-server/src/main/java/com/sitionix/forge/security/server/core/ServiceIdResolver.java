package com.sitionix.forge.security.server.core;

import com.sitionix.forge.security.server.config.ForgeSecurityServerProperties;
import org.springframework.util.StringUtils;

import java.net.URI;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

public class ServiceIdResolver {

    private final Map<String, String> aliasToServiceId;
    private final Set<String> serviceIds;

    public ServiceIdResolver(final ForgeSecurityServerProperties properties) {
        final Map<String, String> aliasMap = new HashMap<>();
        final Set<String> ids = new HashSet<>();
        final Map<String, ForgeSecurityServerProperties.ServiceDefinition> services =
                properties == null ? null : properties.getServices();
        if (services != null) {
            services.forEach((key, service) -> {
                if (service == null || !StringUtils.hasText(service.getId())) {
                    return;
                }
                final String normalizedId = this.normalize(service.getId());
                if (StringUtils.hasText(normalizedId)) {
                    aliasMap.put(normalizedId, normalizedId);
                    ids.add(normalizedId);
                }
                if (service.getHosts() == null) {
                    return;
                }
                for (final String host : service.getHosts()) {
                    final String normalizedHost = this.normalize(this.stripPort(host));
                    if (StringUtils.hasText(normalizedHost)) {
                        aliasMap.put(normalizedHost, normalizedId);
                    }
                }
            });
        }
        this.aliasToServiceId = Map.copyOf(aliasMap);
        this.serviceIds = Set.copyOf(ids);
    }

    public String resolveServiceId(final String host) {
        final String normalized = this.normalize(this.extractHost(host));
        if (!StringUtils.hasText(normalized)) {
            return null;
        }
        return this.aliasToServiceId.get(normalized);
    }

    public boolean isServiceId(final String value) {
        final String normalized = this.normalize(value);
        if (!StringUtils.hasText(normalized)) {
            return false;
        }
        return this.serviceIds.contains(normalized);
    }

    public boolean hasServiceIds() {
        return !this.serviceIds.isEmpty();
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
