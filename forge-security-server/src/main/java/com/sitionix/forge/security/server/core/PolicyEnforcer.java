package com.sitionix.forge.security.server.core;

import com.sitionix.forge.security.server.config.ForgeSecurityServerProperties;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.StringUtils;

import java.util.List;
import java.util.Map;

public class PolicyEnforcer {

    private final ForgeSecurityServerProperties properties;
    private final AntPathMatcher pathMatcher = new AntPathMatcher();

    public PolicyEnforcer(final ForgeSecurityServerProperties properties) {
        this.properties = properties;
    }

    public void assertAllowed(final ServiceIdentity identity, final String requestMethod, final String requestPath) {
        if (identity == null || !StringUtils.hasText(identity.serviceName())) {
            throw new AccessDeniedException("Internal service identity missing");
        }
        final Map<String, ForgeSecurityServerProperties.Policy> policies = this.properties.getPolicies();
        if (policies == null || policies.isEmpty()) {
            throw new AccessDeniedException("Internal service identity not permitted");
        }
        final ForgeSecurityServerProperties.Policy policy = policies.get(identity.serviceName());
        if (policy == null || policy.getAllow() == null || policy.getAllow().isEmpty()) {
            throw new AccessDeniedException("Internal service identity not permitted");
        }
        if (this.isAllowAll(policy.getAllow())) {
            return;
        }
        if (this.isEndpointAllowed(policy.getAllow(), requestMethod, requestPath)) {
            return;
        }
        throw new AccessDeniedException("Internal service identity not permitted");
    }

    private boolean isAllowAll(final List<String> allowEntries) {
        for (final String entry : allowEntries) {
            if (StringUtils.hasText(entry) && "*".equals(entry.trim())) {
                return true;
            }
        }
        return false;
    }

    private boolean isEndpointAllowed(final List<String> allowEntries,
                                      final String requestMethod,
                                      final String requestPath) {
        if (!StringUtils.hasText(requestMethod) || !StringUtils.hasText(requestPath)) {
            return false;
        }
        for (final String entry : allowEntries) {
            if (!StringUtils.hasText(entry)) {
                continue;
            }
            final String normalized = this.stripScope(entry.trim());
            if (!StringUtils.hasText(normalized) || "*".equals(normalized)) {
                continue;
            }
            final String[] parts = normalized.split("\\s+", 2);
            if (parts.length != 2) {
                continue;
            }
            final String method = parts[0].trim();
            final String path = parts[1].trim();
            if (!StringUtils.hasText(method) || !StringUtils.hasText(path)) {
                continue;
            }
            if (!method.equalsIgnoreCase(requestMethod)) {
                continue;
            }
            if (this.pathMatcher.match(path, requestPath)) {
                return true;
            }
        }
        return false;
    }

    private String stripScope(final String entry) {
        final int scopeIndex = entry.indexOf(':');
        if (scopeIndex > 0) {
            return entry.substring(0, scopeIndex).trim();
        }
        return entry;
    }
}
