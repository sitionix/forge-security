package com.sitionix.forge.security.server.web;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.util.StringUtils;

final class ForgeSecurityRequestHelper {

    private ForgeSecurityRequestHelper() {
    }

    static String resolvePath(final HttpServletRequest request) {
        String path = request.getRequestURI();
        final String contextPath = request.getContextPath();
        if (StringUtils.hasText(contextPath) && path.startsWith(contextPath)) {
            path = path.substring(contextPath.length());
        }
        return path;
    }
}
