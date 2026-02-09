package com.sitionix.forge.security.userjwt.web;

import com.sitionix.forge.security.userjwt.core.UserJwtVerificationException;
import com.sitionix.forge.security.userjwt.core.UserJwtVerifier;
import com.sitionix.forge.security.userjwt.core.ForgeUser;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class ForgeUserJwtFilter extends OncePerRequestFilter {

    private final UserJwtVerifier verifier;
    private final UserJwtErrorResponseWriter errorResponseWriter;

    public ForgeUserJwtFilter(final UserJwtVerifier verifier,
                              final UserJwtErrorResponseWriter errorResponseWriter) {
        this.verifier = verifier;
        this.errorResponseWriter = errorResponseWriter;
    }

    @Override
    protected void doFilterInternal(final HttpServletRequest request,
                                    final HttpServletResponse response,
                                    final FilterChain filterChain) throws ServletException, IOException {
        final String header = request.getHeader("Authorization");
        if (!StringUtils.hasText(header)) {
            filterChain.doFilter(request, response);
            return;
        }
        final String prefix = "Bearer ";
        if (!header.regionMatches(true, 0, prefix, 0, prefix.length())) {
            filterChain.doFilter(request, response);
            return;
        }
        final String token = header.substring(prefix.length()).trim();
        if (!StringUtils.hasText(token)) {
            filterChain.doFilter(request, response);
            return;
        }
        if (!this.verifier.looksLikeUserJwt(token)) {
            filterChain.doFilter(request, response);
            return;
        }
        try {
            final ForgeUser user = this.verifier.validateUserJwt(token);
            SecurityContextHolder.getContext()
                    .setAuthentication(UserJwtAuthenticationToken.authenticated(user));
            filterChain.doFilter(request, response);
        } catch (final UserJwtVerificationException ex) {
            SecurityContextHolder.clearContext();
            this.errorResponseWriter.write(response, HttpServletResponse.SC_UNAUTHORIZED,
                    "unauthorized", "Invalid token");
        }
    }
}
