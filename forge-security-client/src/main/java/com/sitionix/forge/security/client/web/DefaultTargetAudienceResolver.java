package com.sitionix.forge.security.client.web;

import com.sitionix.forge.security.client.core.TargetAudienceResolver;
import org.springframework.http.HttpRequest;
import org.springframework.util.StringUtils;

import java.net.URI;

public class DefaultTargetAudienceResolver implements TargetAudienceResolver {

    @Override
    public String resolve(final HttpRequest request) {
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
