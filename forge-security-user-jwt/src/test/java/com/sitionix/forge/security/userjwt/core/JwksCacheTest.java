package com.sitionix.forge.security.userjwt.core;

import com.sitionix.forge.security.userjwt.client.JwksClient;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class JwksCacheTest {

    @Mock
    private JwksClient jwksClient;

    private MutableClock clock;
    private JwksCache jwksCache;

    @BeforeEach
    void setUp() {
        final Instant now = Instant.parse("2024-01-01T00:00:00Z");
        this.clock = new MutableClock(now, ZoneOffset.UTC);
        this.jwksCache = new JwksCache(this.jwksClient, Duration.ofSeconds(10), this.clock);
    }

    @AfterEach
    void tearDown() {
        verifyNoMoreInteractions(this.jwksClient);
    }

    @Test
    void givenCacheExpired_whenGetKey_thenRefreshesAndCaches() throws Exception {
        //given
        final RSAPublicKey publicKey = this.getPublicKey();
        when(this.jwksClient.fetchKeys())
                .thenReturn(Map.of("kid-1", publicKey), Map.of("kid-1", publicKey));

        //when
        final RSAPublicKey first = this.jwksCache.getKey("kid-1");
        final RSAPublicKey second = this.jwksCache.getKey("kid-1");
        this.clock.advance(Duration.ofSeconds(11));
        final RSAPublicKey third = this.jwksCache.getKey("kid-1");

        //then
        assertThat(first).isNotNull();
        assertThat(second).isNotNull();
        assertThat(third).isNotNull();
        verify(this.jwksClient, times(2)).fetchKeys();
    }

    @Test
    void givenUnknownKid_whenGetKey_thenRefreshesOnceAndReturnsNull() throws Exception {
        //given
        final RSAPublicKey publicKey = this.getPublicKey();
        when(this.jwksClient.fetchKeys())
                .thenReturn(Map.of("kid-1", publicKey), Map.of("kid-1", publicKey));

        //when
        final RSAPublicKey known = this.jwksCache.getKey("kid-1");
        final RSAPublicKey missing = this.jwksCache.getKey("kid-2");

        //then
        assertThat(known).isNotNull();
        assertThat(missing).isNull();
        verify(this.jwksClient, times(2)).fetchKeys();
    }

    private RSAPublicKey getPublicKey() throws NoSuchAlgorithmException {
        final KeyPair keyPair = this.generateKeyPair();
        return (RSAPublicKey) keyPair.getPublic();
    }

    private KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        final KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }
}
