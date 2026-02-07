package com.sitionix.forge.security.userjwt.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;

public class UserJwtErrorResponseWriter {

    private final ObjectMapper objectMapper;

    public UserJwtErrorResponseWriter(final ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public void write(final HttpServletResponse response,
                      final int status,
                      final String error,
                      final String message) throws IOException {
        if (response.isCommitted()) {
            return;
        }
        response.setStatus(status);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");
        final Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("code", status);
        payload.put("title", error);
        payload.put("details", message);
        this.objectMapper.writeValue(response.getWriter(), payload);
    }
}
