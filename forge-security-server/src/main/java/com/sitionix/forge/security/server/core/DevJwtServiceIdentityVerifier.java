package com.sitionix.forge.security.server.core;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.sitionix.forge.security.server.config.ForgeSecurityMode;
import com.sitionix.forge.security.server.config.ForgeSecurityServerProperties;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

public class DevJwtServiceIdentityVerifier implements ServiceIdentityVerifier {

    private final ForgeSecurityServerProperties properties;
    private final ServiceIdResolver serviceIdResolver;

    private JWTVerifier jwtVerifier;

    public DevJwtServiceIdentityVerifier(final ForgeSecurityServerProperties properties,
                                         final ServiceIdResolver serviceIdResolver) {
        this.properties = properties;
        this.serviceIdResolver = serviceIdResolver;
    }

    @PostConstruct
    void init() {
        if (this.properties.getMode() != ForgeSecurityMode.DEV_JWT) {
            return;
        }
        final ForgeSecurityServerProperties.DevJwt devConfig = this.properties.getDev();
        if (!StringUtils.hasText(devConfig.getJwtSecret())) {
            return;
        }
        final Algorithm algorithm = Algorithm.HMAC256(devConfig.getJwtSecret());
        this.jwtVerifier = JWT.require(algorithm)
                .withIssuer(devConfig.getIssuer())
                .build();
    }

    @Override
    public ServiceIdentity verify(final HttpServletRequest request) {
        final String token = this.extractBearerToken(request);
        if (!StringUtils.hasText(token)) {
            throw new BadCredentialsException("Missing internal authorization token");
        }
        if (this.jwtVerifier == null) {
            throw new BadCredentialsException("Internal authorization verifier not configured");
        }
        final DecodedJWT verified = this.verifyToken(token);
        final String subject = verified.getSubject();
        if (!StringUtils.hasText(subject)) {
            throw new BadCredentialsException("Internal authorization token missing subject");
        }
        if (!this.serviceIdResolver.isServiceId(subject)) {
            throw new BadCredentialsException("Invalid internal authorization token");
        }
        if (verified.getIssuedAt() == null || verified.getExpiresAt() == null) {
            throw new BadCredentialsException("Internal authorization token missing iat/exp");
        }
        if (verified.getExpiresAt().toInstant().isBefore(Instant.now())) {
            throw new BadCredentialsException("Internal authorization token expired");
        }
        final List<String> audiences = verified.getAudience();
        if (!this.isAudienceAccepted(audiences)) {
            throw new BadCredentialsException("Invalid internal authorization token");
        }
        final String audience = this.resolveAudience(audiences);
        final List<String> scopes = this.extractScopes(verified);

        return new ServiceIdentity(subject,
                scopes,
                verified.getIssuedAt().toInstant(),
                verified.getExpiresAt().toInstant(),
                verified.getIssuer(),
                audience,
                false);
    }

    private DecodedJWT verifyToken(final String token) {
        try {
            return this.jwtVerifier.verify(token);
        } catch (final JWTVerificationException ex) {
            throw new BadCredentialsException("Invalid internal authorization token");
        }
    }

    private boolean isAudienceAccepted(final List<String> audiences) {
        final List<String> acceptedAudiences = this.getAcceptedAudiences();
        if (acceptedAudiences.isEmpty()) {
            return false;
        }
        if (audiences == null || audiences.isEmpty()) {
            return false;
        }
        for (final String audience : audiences) {
            if (!StringUtils.hasText(audience)) {
                continue;
            }
            final String normalized = this.normalize(audience);
            if (acceptedAudiences.contains(normalized)) {
                if (!this.serviceIdResolver.isServiceId(audience)) {
                    return false;
                }
                return true;
            }
        }
        return false;
    }

    private String extractBearerToken(final HttpServletRequest request) {
        final String header = request.getHeader("Authorization");
        if (!StringUtils.hasText(header)) {
            return null;
        }
        final String prefix = "Bearer ";
        if (!header.regionMatches(true, 0, prefix, 0, prefix.length())) {
            return null;
        }
        final String token = header.substring(prefix.length()).trim();
        return StringUtils.hasText(token) ? token : null;
    }

    private List<String> extractScopes(final DecodedJWT decodedJWT) {
        final List<String> scopes = new ArrayList<>();
        final Claim scopeClaim = decodedJWT.getClaim("scope");
        if (scopeClaim != null && !scopeClaim.isNull()) {
            final String scopeValue = scopeClaim.asString();
            if (StringUtils.hasText(scopeValue)) {
                Collections.addAll(scopes, scopeValue.trim().split("\\s+"));
            } else {
                final List<String> scopeList = scopeClaim.asList(String.class);
                if (scopeList != null) {
                    scopes.addAll(scopeList);
                }
            }
        }
        if (scopes.isEmpty()) {
            final Claim scpClaim = decodedJWT.getClaim("scp");
            if (scpClaim != null && !scpClaim.isNull()) {
                final List<String> scopeList = scpClaim.asList(String.class);
                if (scopeList != null) {
                    scopes.addAll(scopeList);
                }
            }
        }
        return scopes;
    }

    private String resolveAudience(final List<String> audiences) {
        if (audiences == null || audiences.isEmpty()) {
            return null;
        }
        for (final String audience : audiences) {
            if (!StringUtils.hasText(audience)) {
                continue;
            }
            return audience;
        }
        return null;
    }

    private String normalize(final String value) {
        if (!StringUtils.hasText(value)) {
            return null;
        }
        return value.trim().toLowerCase(Locale.ROOT);
    }

    private List<String> getAcceptedAudiences() {
        final List<String> acceptedAudiences = this.properties.getAcceptedAudiences();
        if (acceptedAudiences == null || acceptedAudiences.isEmpty()) {
            final String serviceId = this.properties.getServiceId();
            if (StringUtils.hasText(serviceId)) {
                return List.of(this.normalize(serviceId));
            }
            return List.of();
        }
        return acceptedAudiences.stream()
                .filter(StringUtils::hasText)
                .map(this::normalize)
                .toList();
    }
}
