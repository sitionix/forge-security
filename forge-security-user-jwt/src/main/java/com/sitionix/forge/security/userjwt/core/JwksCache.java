package com.sitionix.forge.security.userjwt.core;

import com.sitionix.forge.security.userjwt.client.JwksClient;
import com.sitionix.forge.security.userjwt.client.JwksClientException;
import org.springframework.util.StringUtils;

import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;

public class JwksCache {

    private final JwksClient jwksClient;
    private final Duration ttl;
    private final Clock clock;
    private final ReentrantLock refreshLock = new ReentrantLock();

    private volatile CacheState state = CacheState.empty();

    public JwksCache(final JwksClient jwksClient, final Duration ttl, final Clock clock) {
        this.jwksClient = jwksClient;
        this.ttl = ttl;
        this.clock = clock;
    }

    public RSAPublicKey getKey(final String kid) {
        if (!StringUtils.hasText(kid)) {
            return null;
        }
        final Instant now = Instant.now(this.clock);
        CacheState current = this.state;
        boolean refreshed = false;

        if (current.isExpired(now)) {
            this.refreshIfNeeded(now, current, false);
            refreshed = true;
            current = this.state;
        }

        RSAPublicKey key = current.keys().get(kid);
        if (key == null && !refreshed) {
            this.refreshIfNeeded(now, current, true);
            current = this.state;
            key = current.keys().get(kid);
        }
        return key;
    }

    private void refreshIfNeeded(final Instant now, final CacheState observed, final boolean force) {
        this.refreshLock.lock();
        try {
            final CacheState current = this.state;
            if (current != observed) {
                return;
            }
            if (!force && !current.isExpired(now)) {
                return;
            }
            final Map<String, RSAPublicKey> fetched = this.jwksClient.fetchKeys();
            if (fetched == null || fetched.isEmpty()) {
                throw new JwksClientException("JWKS response did not contain any keys");
            }
            final Map<String, RSAPublicKey> safeCopy = Collections.unmodifiableMap(new HashMap<>(fetched));
            this.state = new CacheState(safeCopy, now.plus(this.ttl));
        } finally {
            this.refreshLock.unlock();
        }
    }

    private record CacheState(Map<String, RSAPublicKey> keys, Instant expiresAt) {

        static CacheState empty() {
            return new CacheState(Collections.emptyMap(), Instant.EPOCH);
        }

        boolean isExpired(final Instant now) {
            return this.expiresAt == null || now.isAfter(this.expiresAt);
        }
    }
}
