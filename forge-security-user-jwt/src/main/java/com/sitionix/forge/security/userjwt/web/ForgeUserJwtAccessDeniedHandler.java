package com.sitionix.forge.security.userjwt.web;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;

import java.io.IOException;

public class ForgeUserJwtAccessDeniedHandler implements AccessDeniedHandler {

    private final UserJwtErrorResponseWriter errorResponseWriter;

    public ForgeUserJwtAccessDeniedHandler(final UserJwtErrorResponseWriter errorResponseWriter) {
        this.errorResponseWriter = errorResponseWriter;
    }

    @Override
    public void handle(final HttpServletRequest request,
                       final HttpServletResponse response,
                       final AccessDeniedException accessDeniedException) throws IOException {
        this.errorResponseWriter.write(response, HttpServletResponse.SC_FORBIDDEN,
                "forbidden", "Forbidden");
    }
}
