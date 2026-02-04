package com.sitionix.forge.security.client.web;

import com.sitionix.forge.security.client.core.ServiceIdResolver;
import com.sitionix.forge.security.client.core.TargetAudienceResolver;
import org.springframework.http.HttpRequest;
import org.springframework.util.StringUtils;

import java.net.URI;

public class DefaultTargetAudienceResolver implements TargetAudienceResolver {

    private final ServiceIdResolver serviceIdResolver;

    public DefaultTargetAudienceResolver(final ServiceIdResolver serviceIdResolver) {
        this.serviceIdResolver = serviceIdResolver;
    }

    @Override
    public String resolve(final HttpRequest request) {
        final String host = this.extractHost(request);
        final String serviceId = this.serviceIdResolver.resolveServiceId(host);
        if (!StringUtils.hasText(serviceId)) {
            throw new SecurityException("Unable to resolve target service id for host: " + host);
        }
        return serviceId;
    }

    private String extractHost(final HttpRequest request) {
        if (request == null) {
            return null;
        }
        final URI uri = request.getURI();
        if (uri == null) {
            return null;
        }
        String host = uri.getHost();
        if (!StringUtils.hasText(host)) {
            host = uri.getAuthority();
        }
        return StringUtils.hasText(host) ? host : null;
    }
}
