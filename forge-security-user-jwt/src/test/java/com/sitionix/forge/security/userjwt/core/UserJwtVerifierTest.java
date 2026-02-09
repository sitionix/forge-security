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
import static org.assertj.core.api.Assertions.assertThatThrownBy;
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

    @Test
    void givenValidRs256Token_whenLooksLikeUserJwt_thenReturnsTrue() {
        //given
        final String token = this.issueToken();

        //when
        final boolean result = this.userJwtVerifier.looksLikeUserJwt(token);

        //then
        assertThat(result).isTrue();
    }

    @Test
    void givenHs256Token_whenLooksLikeUserJwt_thenReturnsFalse() {
        //given
        final String token = this.issueServiceToken();

        //when
        final boolean result = this.userJwtVerifier.looksLikeUserJwt(token);

        //then
        assertThat(result).isFalse();
    }

    @Test
    void givenGarbageToken_whenLooksLikeUserJwt_thenReturnsFalse() {
        //given
        final String token = "not-a-jwt-token";

        //when
        final boolean result = this.userJwtVerifier.looksLikeUserJwt(token);

        //then
        assertThat(result).isFalse();
    }

    @Test
    void givenRs256TokenWithoutKid_whenLooksLikeUserJwt_thenReturnsFalse() {
        //given
        final String token = this.issueTokenWithoutKid();

        //when
        final boolean result = this.userJwtVerifier.looksLikeUserJwt(token);

        //then
        assertThat(result).isFalse();
    }

    @Test
    void givenRs256TokenWithoutSubject_whenLooksLikeUserJwt_thenReturnsFalse() {
        //given
        final String token = this.issueTokenWithoutSubject();

        //when
        final boolean result = this.userJwtVerifier.looksLikeUserJwt(token);

        //then
        assertThat(result).isFalse();
    }

    @Test
    void givenRs256TokenWithWrongIssuer_whenLooksLikeUserJwt_thenReturnsFalse() {
        //given
        final String token = this.issueTokenWithIssuer("other-issuer");

        //when
        final boolean result = this.userJwtVerifier.looksLikeUserJwt(token);

        //then
        assertThat(result).isFalse();
    }

    @Test
    void givenRs256TokenWithWrongAudience_whenLooksLikeUserJwt_thenReturnsFalse() {
        //given
        final String token = this.issueTokenWithAudience("other-audience");

        //when
        final boolean result = this.userJwtVerifier.looksLikeUserJwt(token);

        //then
        assertThat(result).isFalse();
    }

    @Test
    void givenExpiredToken_whenVerify_thenThrowsException() {
        //given
        final String token = this.issueTokenWithExpiry(this.now.minusSeconds(120));
        when(this.jwksCache.getKey(this.kid)).thenReturn(this.publicKey);

        //when
        assertThatThrownBy(() -> this.userJwtVerifier.verify(token))
                .isInstanceOf(UserJwtVerificationException.class);

        //then
        verify(this.jwksCache, times(1)).getKey(this.kid);
    }

    @Test
    void givenTokenWithInvalidSignature_whenVerify_thenThrowsException() throws Exception {
        //given
        final String token = this.issueTokenWithInvalidSignature();
        when(this.jwksCache.getKey(this.kid)).thenReturn(this.publicKey);

        //when
        assertThatThrownBy(() -> this.userJwtVerifier.verify(token))
                .isInstanceOf(UserJwtVerificationException.class);

        //then
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

    private String issueServiceToken() {
        return JWT.create()
                .withKeyId(this.kid)
                .withSubject("service-123")
                .sign(Algorithm.HMAC256("secret"));
    }

    private String issueTokenWithoutKid() {
        return JWT.create()
                .withSubject("user-123")
                .withIssuer("auth-service")
                .withAudience("bff")
                .withIssuedAt(Date.from(this.now.minusSeconds(5)))
                .withExpiresAt(Date.from(this.now.plusSeconds(300)))
                .sign(Algorithm.RSA256(this.publicKey, this.privateKey));
    }

    private String issueTokenWithoutSubject() {
        return JWT.create()
                .withKeyId(this.kid)
                .withIssuer("auth-service")
                .withAudience("bff")
                .withIssuedAt(Date.from(this.now.minusSeconds(5)))
                .withExpiresAt(Date.from(this.now.plusSeconds(300)))
                .sign(Algorithm.RSA256(this.publicKey, this.privateKey));
    }

    private String issueTokenWithIssuer(final String issuer) {
        return JWT.create()
                .withKeyId(this.kid)
                .withSubject("user-123")
                .withIssuer(issuer)
                .withAudience("bff")
                .withIssuedAt(Date.from(this.now.minusSeconds(5)))
                .withExpiresAt(Date.from(this.now.plusSeconds(300)))
                .sign(Algorithm.RSA256(this.publicKey, this.privateKey));
    }

    private String issueTokenWithAudience(final String audience) {
        return JWT.create()
                .withKeyId(this.kid)
                .withSubject("user-123")
                .withIssuer("auth-service")
                .withAudience(audience)
                .withIssuedAt(Date.from(this.now.minusSeconds(5)))
                .withExpiresAt(Date.from(this.now.plusSeconds(300)))
                .sign(Algorithm.RSA256(this.publicKey, this.privateKey));
    }

    private String issueTokenWithInvalidSignature() throws NoSuchAlgorithmException {
        final KeyPair invalidKeyPair = this.generateKeyPair();
        final RSAPrivateKey invalidPrivateKey = (RSAPrivateKey) invalidKeyPair.getPrivate();
        return JWT.create()
                .withKeyId(this.kid)
                .withSubject("user-123")
                .withIssuer("auth-service")
                .withAudience("bff")
                .withIssuedAt(Date.from(this.now.minusSeconds(5)))
                .withExpiresAt(Date.from(this.now.plusSeconds(300)))
                .sign(Algorithm.RSA256(this.publicKey, invalidPrivateKey));
    }

    private String issueTokenWithExpiry(final Instant expiresAt) {
        return JWT.create()
                .withKeyId(this.kid)
                .withSubject("user-123")
                .withIssuer("auth-service")
                .withAudience("bff")
                .withIssuedAt(Date.from(this.now.minusSeconds(5)))
                .withExpiresAt(Date.from(expiresAt))
                .withClaim("email", "user@example.com")
                .sign(Algorithm.RSA256(this.publicKey, this.privateKey));
    }

    private KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        final KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }
}
