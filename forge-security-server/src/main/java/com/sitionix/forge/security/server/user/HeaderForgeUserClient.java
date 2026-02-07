package com.sitionix.forge.security.server.user;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

@Component
public class HeaderForgeUserClient implements ForgeUserClient {

    private static final String USER_ID_HEADER = "X-Forge-User-Sub";

    private final ObjectProvider<HttpServletRequest> requestProvider;

    public HeaderForgeUserClient(final ObjectProvider<HttpServletRequest> requestProvider) {
        this.requestProvider = requestProvider;
    }

    @Override
    public Long getUserId() {
        final HttpServletRequest request = this.requestProvider.getIfAvailable();
        if (request == null) {
            throw new BadCredentialsException("Authentication required.");
        }
        final String headerValue = request.getHeader(USER_ID_HEADER);
        if (!StringUtils.hasText(headerValue)) {
            throw new BadCredentialsException("Authentication required.");
        }
        try {
            return Long.valueOf(headerValue);
        } catch (final NumberFormatException ex) {
            throw new BadCredentialsException("Authentication required.");
        }
    }
}
