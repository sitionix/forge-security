package com.sitionix.forge.security.server.core;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.Verification;
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

public class DevJwtServiceIdentityVerifier implements ServiceIdentityVerifier {

    private final ForgeSecurityServerProperties properties;

    private JWTVerifier jwtVerifier;

    public DevJwtServiceIdentityVerifier(final ForgeSecurityServerProperties properties) {
        this.properties = properties;
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
        final List<String> audiences = this.getAcceptedAudiences(devConfig);
        final Verification verification = JWT.require(algorithm)
                .withIssuer(devConfig.getIssuer());
        if (!audiences.isEmpty()) {
            verification.withAudience(audiences.toArray(String[]::new));
        }
        this.jwtVerifier = verification.build();
    }

    @Override
    public ServiceIdentity verify(final HttpServletRequest request) {
        final String token = this.extractBearerToken(request);
        if (!StringUtils.hasText(token)) {
            throw new BadCredentialsException("Missing internal authorization token");
        }
        final DecodedJWT decoded = this.decodeToken(token);
        if (this.isBypassToken(decoded, token)) {
            return this.buildBypassIdentity(decoded);
        }
        if (this.jwtVerifier == null) {
            throw new BadCredentialsException("Internal authorization verifier not configured");
        }
        final DecodedJWT verified = this.verifyToken(token);
        final String subject = verified.getSubject();
        if (!StringUtils.hasText(subject)) {
            throw new BadCredentialsException("Internal authorization token missing subject");
        }
        if (verified.getIssuedAt() == null || verified.getExpiresAt() == null) {
            throw new BadCredentialsException("Internal authorization token missing iat/exp");
        }
        if (verified.getExpiresAt().toInstant().isBefore(Instant.now())) {
            throw new BadCredentialsException("Internal authorization token expired");
        }
        final List<String> audiences = verified.getAudience();
        final String audience = audiences == null || audiences.isEmpty() ? null : audiences.get(0);
        final List<String> scopes = this.extractScopes(verified);

        return new ServiceIdentity(subject,
                scopes,
                verified.getIssuedAt().toInstant(),
                verified.getExpiresAt().toInstant(),
                verified.getIssuer(),
                audience,
                false);
    }

    private DecodedJWT decodeToken(final String token) {
        try {
            return JWT.decode(token);
        } catch (final Exception ex) {
            throw new BadCredentialsException("Invalid internal authorization token");
        }
    }

    private DecodedJWT verifyToken(final String token) {
        try {
            return this.jwtVerifier.verify(token);
        } catch (final JWTVerificationException ex) {
            throw new BadCredentialsException("Invalid internal authorization token");
        }
    }

    private boolean isBypassToken(final DecodedJWT decoded, final String rawToken) {
        final ForgeSecurityServerProperties.DevJwt devConfig = this.properties.getDev();
        final String bypassKid = this.resolveBypassKid(devConfig);
        if (!StringUtils.hasText(bypassKid)) {
            return false;
        }
        if (!bypassKid.equals(decoded.getKeyId())) {
            return false;
        }
        final String staticToken = devConfig.getStaticToken();
        return !StringUtils.hasText(staticToken) || staticToken.equals(rawToken);
    }

    private ServiceIdentity buildBypassIdentity(final DecodedJWT decoded) {
        final ForgeSecurityServerProperties.DevJwt devConfig = this.properties.getDev();
        final String subject = decoded.getSubject();
        if (!StringUtils.hasText(subject)) {
            throw new BadCredentialsException("Internal authorization token missing subject");
        }
        if (!StringUtils.hasText(decoded.getIssuer()) || !decoded.getIssuer().equals(devConfig.getIssuer())) {
            throw new BadCredentialsException("Invalid internal authorization token");
        }
        final Instant issuedAt = decoded.getIssuedAt() == null ? null : decoded.getIssuedAt().toInstant();
        if (issuedAt == null) {
            throw new BadCredentialsException("Internal authorization token missing iat");
        }
        final Instant expiresAt = decoded.getExpiresAt() == null ? null : decoded.getExpiresAt().toInstant();
        if (!devConfig.isItIgnoreExpiry()) {
            if (expiresAt == null) {
                throw new BadCredentialsException("Internal authorization token missing exp");
            }
            if (expiresAt.isBefore(Instant.now())) {
                throw new BadCredentialsException("Internal authorization token expired");
            }
        }
        final List<String> audiences = decoded.getAudience();
        final String audience = audiences == null || audiences.isEmpty() ? null : audiences.get(0);
        if (!this.isAudienceAccepted(audiences)) {
            throw new BadCredentialsException("Invalid internal authorization token");
        }
        final List<String> scopes = this.extractScopes(decoded);
        return new ServiceIdentity(subject,
                scopes,
                issuedAt,
                expiresAt,
                decoded.getIssuer(),
                audience,
                devConfig.isItBypassPolicies());
    }

    private String resolveBypassKid(final ForgeSecurityServerProperties.DevJwt devConfig) {
        if (StringUtils.hasText(devConfig.getStaticToken())) {
            final DecodedJWT staticDecoded = this.decodeToken(devConfig.getStaticToken());
            return staticDecoded.getKeyId();
        }
        if (devConfig.isItKidBypassEnabled()) {
            return devConfig.getItKid();
        }
        return null;
    }

    private boolean isAudienceAccepted(final List<String> audiences) {
        final ForgeSecurityServerProperties.DevJwt devConfig = this.properties.getDev();
        if (StringUtils.hasText(devConfig.getStaticToken())) {
            return true;
        }
        final List<String> acceptedAudiences = this.getAcceptedAudiences(devConfig);
        if (acceptedAudiences.isEmpty()) {
            return true;
        }
        if (audiences == null || audiences.isEmpty()) {
            return false;
        }
        for (final String audience : audiences) {
            if (acceptedAudiences.contains(audience)) {
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

    private List<String> getAcceptedAudiences(final ForgeSecurityServerProperties.DevJwt devConfig) {
        if (devConfig.getAcceptedAudiences() == null || devConfig.getAcceptedAudiences().isEmpty()) {
            if (StringUtils.hasText(this.properties.getServiceName())) {
                return List.of(this.properties.getServiceName());
            }
            return List.of();
        }
        return devConfig.getAcceptedAudiences();
    }
}
