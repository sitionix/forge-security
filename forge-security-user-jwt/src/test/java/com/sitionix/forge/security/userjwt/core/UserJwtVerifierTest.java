package com.sitionix.forge.security.userjwt.core;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.sitionix.forge.security.userjwt.config.ForgeUserJwtProperties;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class UserJwtVerifierTest {

    @Mock
    private JwksCache jwksCache;

    private ForgeUserJwtProperties properties;
    private UserJwtVerifier userJwtVerifier;
    private Clock clock;
    private RSAPublicKey publicKey;
    private RSAPrivateKey privateKey;
    private String kid;
    private Instant now;

    @BeforeEach
    void setUp() throws Exception {
        this.now = Instant.parse("2024-01-01T00:00:00Z");
        this.clock = Clock.fixed(this.now, ZoneOffset.UTC);
        this.kid = "kid-1";
        this.properties = new ForgeUserJwtProperties();
        this.properties.setIssuer("auth-service");
        this.properties.setAudience("bff");
        this.properties.setClockSkewSeconds(30);

        final KeyPair keyPair = this.generateKeyPair();
        this.publicKey = (RSAPublicKey) keyPair.getPublic();
        this.privateKey = (RSAPrivateKey) keyPair.getPrivate();

        this.userJwtVerifier = new UserJwtVerifier(this.jwksCache, this.properties, this.clock);
    }

    @AfterEach
    void tearDown() {
        verifyNoMoreInteractions(this.jwksCache);
    }

    @Test
    void givenValidRs256Token_whenVerify_thenReturnsPrincipal() {
        //given
        final String token = this.issueToken();
        when(this.jwksCache.getKey(this.kid)).thenReturn(this.publicKey);

        //when
        final ForgeUser user = this.userJwtVerifier.verify(token);

        //then
        assertThat(user.getSubject()).isEqualTo("user-123");
        assertThat(user.getEmail()).isEqualTo("user@example.com");
        verify(this.jwksCache, times(1)).getKey(this.kid);
    }

    private String issueToken() {
        return JWT.create()
                .withKeyId(this.kid)
                .withSubject("user-123")
                .withIssuer("auth-service")
                .withAudience("bff")
                .withIssuedAt(Date.from(this.now.minusSeconds(5)))
                .withExpiresAt(Date.from(this.now.plusSeconds(300)))
                .withClaim("email", "user@example.com")
                .sign(Algorithm.RSA256(this.publicKey, this.privateKey));
    }

    private KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        final KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }
}
