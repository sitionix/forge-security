package com.sitionix.forge.security.userjwt.web;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import java.io.IOException;

public class ForgeUserJwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final UserJwtErrorResponseWriter errorResponseWriter;

    public ForgeUserJwtAuthenticationEntryPoint(final UserJwtErrorResponseWriter errorResponseWriter) {
        this.errorResponseWriter = errorResponseWriter;
    }

    @Override
    public void commence(final HttpServletRequest request,
                         final HttpServletResponse response,
                         final AuthenticationException authException) throws IOException {
        this.errorResponseWriter.write(response, HttpServletResponse.SC_UNAUTHORIZED,
                "unauthorized", "Authentication required");
    }
}
