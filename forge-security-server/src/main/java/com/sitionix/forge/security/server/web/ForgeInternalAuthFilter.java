package com.sitionix.forge.security.server.web;

import com.sitionix.forge.security.server.config.ForgeSecurityMode;
import com.sitionix.forge.security.server.config.ForgeSecurityServerProperties;
import com.sitionix.forge.security.server.core.PolicyEnforcer;
import com.sitionix.forge.security.server.core.ServiceIdentity;
import com.sitionix.forge.security.server.core.ServiceIdentityVerifier;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.util.List;

public class ForgeInternalAuthFilter extends OncePerRequestFilter {

    private final ForgeSecurityServerProperties properties;
    private final ServiceIdentityVerifier devJwtVerifier;
    private final ServiceIdentityVerifier mtlsVerifier;
    private final PolicyEnforcer policyEnforcer;
    private final AntPathMatcher pathMatcher = new AntPathMatcher();

    public ForgeInternalAuthFilter(final ForgeSecurityServerProperties properties,
                                   final ServiceIdentityVerifier devJwtVerifier,
                                   final ServiceIdentityVerifier mtlsVerifier,
                                   final PolicyEnforcer policyEnforcer) {
        this.properties = properties;
        this.devJwtVerifier = devJwtVerifier;
        this.mtlsVerifier = mtlsVerifier;
        this.policyEnforcer = policyEnforcer;
    }

    @Override
    protected void doFilterInternal(final HttpServletRequest request,
                                    final HttpServletResponse response,
                                    final FilterChain filterChain) throws ServletException, IOException {
        if (!this.properties.getServer().isEnabled() || this.isExcluded(request)) {
            filterChain.doFilter(request, response);
            return;
        }
        final ServiceIdentity identity = this.authenticate(request);
        if (!identity.policyBypass()) {
            this.policyEnforcer.assertAllowed(identity, request.getMethod(), ForgeSecurityRequestHelper.resolvePath(request));
        }
        SecurityContextHolder.getContext()
                .setAuthentication(ServiceIdentityAuthenticationToken.authenticated(identity));
        filterChain.doFilter(request, response);
    }

    private boolean isExcluded(final HttpServletRequest request) {
        final List<String> excludes = this.properties.getServer().getExcludes();
        if (excludes == null || excludes.isEmpty()) {
            return false;
        }
        final String path = ForgeSecurityRequestHelper.resolvePath(request);
        for (final String exclude : excludes) {
            if (!StringUtils.hasText(exclude)) {
                continue;
            }
            if (this.pathMatcher.match(exclude.trim(), path)) {
                return true;
            }
        }
        return false;
    }

    private ServiceIdentity authenticate(final HttpServletRequest request) {
        final ForgeSecurityMode mode = this.properties.getMode();
        if (mode == ForgeSecurityMode.DEV_JWT) {
            return this.devJwtVerifier.verify(request);
        }
        if (mode == ForgeSecurityMode.MTLS) {
            return this.mtlsVerifier.verify(request);
        }
        throw new AuthenticationCredentialsNotFoundException("Unsupported internal auth mode");
    }
}
