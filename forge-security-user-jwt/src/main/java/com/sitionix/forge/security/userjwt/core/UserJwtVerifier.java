package com.sitionix.forge.security.userjwt.core;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.sitionix.forge.security.userjwt.config.ForgeUserJwtProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.StringUtils;

import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class UserJwtVerifier {

    private static final Logger log = LoggerFactory.getLogger(UserJwtVerifier.class);

    private static final int MAX_HEADER_LENGTH = 4096;

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
        return this.validateUserJwt(token);
    }

    public ForgeUser validateUserJwt(final String token) {
        if (!StringUtils.hasText(token)) {
            throw new UserJwtVerificationException("Missing user token");
        }
        final JwtClaims claims = this.parseClaims(token);
        if (claims == null || !this.looksLikeUserJwt(claims)) {
            throw new UserJwtVerificationException("Invalid user token");
        }
        try {
            final RSAPublicKey key = this.jwksCache.getKey(claims.getKeyId());
            if (key == null) {
                throw new UserJwtVerificationException("Invalid user token");
            }
            this.verifySignature(claims.getDecodedJwt(), key);
            this.validateClaims(claims.getDecodedJwt());
            return this.toUser(claims.getDecodedJwt());
        } catch (final UserJwtVerificationException ex) {
            log.debug("User JWT validation failed: {}", ex.getMessage());
            throw ex;
        } catch (final RuntimeException ex) {
            log.debug("User JWT validation failed: {}", ex.getClass().getSimpleName());
            throw new UserJwtVerificationException("Invalid user token", ex);
        }
    }

    public boolean looksLikeUserJwt(final String token) {
        final JwtClaims claims = this.parseClaims(token);
        if (claims == null) {
            return false;
        }
        return this.looksLikeUserJwt(claims);
    }

    public JwtClaims parseClaims(final String token) {
        if (!StringUtils.hasText(token)) {
            return null;
        }
        if (!this.hasValidHeaderLength(token)) {
            return null;
        }
        try {
            final DecodedJWT decoded = JWT.decode(token);
            return new JwtClaims(decoded);
        } catch (final Exception ex) {
            return null;
        }
    }

    private boolean looksLikeUserJwt(final JwtClaims claims) {
        if (!"RS256".equalsIgnoreCase(claims.getAlgorithm())) {
            return false;
        }
        if (!StringUtils.hasText(claims.getKeyId())) {
            return false;
        }
        if (!StringUtils.hasText(claims.getSubject())) {
            return false;
        }
        if (StringUtils.hasText(this.properties.getIssuer())) {
            if (!this.properties.getIssuer().trim().equals(claims.getIssuer())) {
                return false;
            }
        }
        if (StringUtils.hasText(this.properties.getAudience())) {
            final List<String> audiences = claims.getAudience();
            if (audiences == null || !audiences.contains(this.properties.getAudience().trim())) {
                return false;
            }
        }
        return true;
    }

    private boolean hasValidHeaderLength(final String token) {
        final int firstDot = token.indexOf('.');
        if (firstDot <= 0) {
            return false;
        }
        if (firstDot > MAX_HEADER_LENGTH) {
            return false;
        }
        return true;
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

    public static final class JwtClaims {

        private final DecodedJWT decodedJwt;
        private final String algorithm;
        private final String keyId;
        private final String subject;
        private final String issuer;
        private final List<String> audience;

        private JwtClaims(final DecodedJWT decodedJwt) {
            this.decodedJwt = decodedJwt;
            this.algorithm = decodedJwt.getAlgorithm();
            this.keyId = decodedJwt.getKeyId();
            this.subject = decodedJwt.getSubject();
            this.issuer = decodedJwt.getIssuer();
            this.audience = decodedJwt.getAudience();
        }

        public DecodedJWT getDecodedJwt() {
            return this.decodedJwt;
        }

        public String getAlgorithm() {
            return this.algorithm;
        }

        public String getKeyId() {
            return this.keyId;
        }

        public String getSubject() {
            return this.subject;
        }

        public String getIssuer() {
            return this.issuer;
        }

        public List<String> getAudience() {
            return this.audience;
        }
    }
}
