package com.sitionix.forge.security.client.core;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.sitionix.forge.security.client.config.ForgeSecurityClientProperties;
import com.sitionix.forge.security.client.config.ForgeSecurityMode;
import org.springframework.util.StringUtils;

import java.time.Clock;
import java.time.Instant;
import java.util.Date;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class ServiceJwtIssuer {

    private static final long EXPIRY_SAFETY_SECONDS = 5L;

    private final ForgeSecurityClientProperties properties;
    private final Clock clock;
    private final Map<String, CachedToken> cache = new ConcurrentHashMap<>();

    public ServiceJwtIssuer(final ForgeSecurityClientProperties properties,
                            final Clock clock) {
        this.properties = properties;
        this.clock = clock;
    }

    public String issueToken(final String audience) {
        if (this.properties.getMode() != ForgeSecurityMode.DEV_JWT) {
            throw new IllegalStateException("Forge security is not in dev-jwt mode");
        }
        final String serviceName = this.properties.getServiceName();
        if (!StringUtils.hasText(serviceName)) {
            throw new IllegalStateException("forge.security.service-name must be configured");
        }
        if (!StringUtils.hasText(audience)) {
            throw new IllegalArgumentException("Audience must be provided");
        }
        final Instant now = Instant.now(this.clock);
        final CachedToken cached = this.cache.get(audience);
        if (cached != null && cached.expiresAt().isAfter(now.plusSeconds(EXPIRY_SAFETY_SECONDS))) {
            return cached.token();
        }
        final Instant expiresAt = now.plusSeconds(this.properties.getDev().getTtlSeconds());
        final Algorithm algorithm = Algorithm.HMAC256(this.properties.getDev().getJwtSecret());
        final String token = JWT.create()
                .withIssuer(this.properties.getDev().getIssuer())
                .withSubject(serviceName)
                .withAudience(audience)
                .withIssuedAt(Date.from(now))
                .withExpiresAt(Date.from(expiresAt))
                .sign(algorithm);
        this.cache.put(audience, new CachedToken(token, expiresAt));
        return token;
    }

    private record CachedToken(String token, Instant expiresAt) {
    }
}
