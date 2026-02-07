package com.sitionix.forge.security.userjwt.core;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.sitionix.forge.security.userjwt.config.ForgeUserJwtProperties;
import org.springframework.util.StringUtils;

import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class UserJwtVerifier {

    private final JwksCache jwksCache;
    private final ForgeUserJwtProperties properties;
    private final Clock clock;

    public UserJwtVerifier(final JwksCache jwksCache,
                           final ForgeUserJwtProperties properties,
                           final Clock clock) {
        this.jwksCache = jwksCache;
        this.properties = properties;
        this.clock = clock;
    }

    public ForgeUser verify(final String token) {
        if (!StringUtils.hasText(token)) {
            throw new UserJwtVerificationException("Missing user token");
        }
        final DecodedJWT decoded;
        try {
            decoded = JWT.decode(token);
        } catch (final Exception ex) {
            throw new UserJwtVerificationException("Invalid user token", ex);
        }
        final String algorithm = decoded.getAlgorithm();
        if (!"RS256".equalsIgnoreCase(algorithm)) {
            throw new UserJwtVerificationException("Invalid user token");
        }
        final String kid = decoded.getKeyId();
        if (!StringUtils.hasText(kid)) {
            throw new UserJwtVerificationException("Invalid user token");
        }
        try {
            final RSAPublicKey key = this.jwksCache.getKey(kid);
            if (key == null) {
                throw new UserJwtVerificationException("Invalid user token");
            }
            this.verifySignature(decoded, key);
            this.validateClaims(decoded);
            return this.toUser(decoded);
        } catch (final UserJwtVerificationException ex) {
            throw ex;
        } catch (final RuntimeException ex) {
            throw new UserJwtVerificationException("Invalid user token", ex);
        }
    }

    private void verifySignature(final DecodedJWT decoded, final RSAPublicKey key) {
        try {
            final Algorithm algorithm = Algorithm.RSA256(key, null);
            algorithm.verify(decoded);
        } catch (final JWTVerificationException ex) {
            throw new UserJwtVerificationException("Invalid user token", ex);
        }
    }

    private void validateClaims(final DecodedJWT verified) {
        final Instant now = Instant.now(this.clock);
        if (verified.getExpiresAt() == null) {
            throw new UserJwtVerificationException("Invalid user token");
        }
        final Instant expiresAt = verified.getExpiresAt().toInstant();
        if (expiresAt.isBefore(now.minusSeconds(this.properties.getClockSkewSeconds()))) {
            throw new UserJwtVerificationException("Invalid user token");
        }
        if (verified.getIssuedAt() != null) {
            final Instant issuedAt = verified.getIssuedAt().toInstant();
            if (issuedAt.isAfter(now.plusSeconds(this.properties.getClockSkewSeconds()))) {
                throw new UserJwtVerificationException("Invalid user token");
            }
        }
        final String subject = verified.getSubject();
        if (!StringUtils.hasText(subject)) {
            throw new UserJwtVerificationException("Invalid user token");
        }
        if (StringUtils.hasText(this.properties.getIssuer())) {
            final String issuer = verified.getIssuer();
            if (!this.properties.getIssuer().trim().equals(issuer)) {
                throw new UserJwtVerificationException("Invalid user token");
            }
        }
        if (StringUtils.hasText(this.properties.getAudience())) {
            final List<String> audiences = verified.getAudience();
            if (audiences == null || !audiences.contains(this.properties.getAudience().trim())) {
                throw new UserJwtVerificationException("Invalid user token");
            }
        }
    }

    private ForgeUser toUser(final DecodedJWT verified) {
        final Map<String, Object> claims = new HashMap<>();
        for (final Map.Entry<String, Claim> entry : verified.getClaims().entrySet()) {
            final Object value = this.toClaimValue(entry.getValue());
            if (value != null) {
                claims.put(entry.getKey(), value);
            }
        }
        final String email = this.resolveEmail(claims);
        final List<String> scopes = this.resolveScopes(claims);
        return new ForgeUser(verified.getSubject(), email, scopes);
    }

    private Object toClaimValue(final Claim claim) {
        if (claim == null || claim.isNull()) {
            return null;
        }
        final String asString = claim.asString();
        if (asString != null) {
            return asString;
        }
        final Integer asInt = claim.asInt();
        if (asInt != null) {
            return asInt;
        }
        final Long asLong = claim.asLong();
        if (asLong != null) {
            return asLong;
        }
        final Double asDouble = claim.asDouble();
        if (asDouble != null) {
            return asDouble;
        }
        final Boolean asBoolean = claim.asBoolean();
        if (asBoolean != null) {
            return asBoolean;
        }
        final List<String> asList = claim.asList(String.class);
        if (asList != null) {
            return asList;
        }
        final Map<String, Object> asMap = claim.asMap();
        if (asMap != null) {
            return asMap;
        }
        return null;
    }

    private String resolveEmail(final Map<String, Object> claims) {
        final Object email = claims.get("email");
        if (email instanceof String value && StringUtils.hasText(value)) {
            return value;
        }
        final Object preferredUsername = claims.get("preferred_username");
        if (preferredUsername instanceof String value && StringUtils.hasText(value)) {
            return value;
        }
        return null;
    }

    private List<String> resolveScopes(final Map<String, Object> claims) {
        final Object scope = claims.get("scope");
        if (scope instanceof String value && StringUtils.hasText(value)) {
            return List.of(value.trim().split("\\s+"));
        }
        final Object scopes = claims.get("scopes");
        if (scopes instanceof List<?> list) {
            return list.stream()
                    .filter(String.class::isInstance)
                    .map(String.class::cast)
                    .filter(StringUtils::hasText)
                    .toList();
        }
        return List.of();
    }
}
