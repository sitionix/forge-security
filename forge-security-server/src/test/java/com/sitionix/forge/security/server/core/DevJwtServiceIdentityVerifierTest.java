package com.sitionix.forge.security.server.core;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.sitionix.forge.security.server.config.ForgeSecurityServerProperties;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.BadCredentialsException;

import java.time.Instant;
import java.util.Date;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DevJwtServiceIdentityVerifierTest {

    @Mock
    private ForgeSecurityServerProperties properties;

    private DevJwtServiceIdentityVerifier verifier;

    @BeforeEach
    void setUp() {
        final ForgeSecurityServerProperties.DevJwt devJwt = this.getDevJwt();
        when(this.properties.getDev()).thenReturn(devJwt);
        this.verifier = new DevJwtServiceIdentityVerifier(this.properties);
        this.verifier.init();
    }

    @AfterEach
    void tearDown() {
        verify(this.properties).getDev();
        verifyNoMoreInteractions(this.properties);
    }

    @Test
    void givenTokenWithWrongAudience_whenVerify_thenThrowsBadCredentialsException() {
        //given
        final String token = this.getToken("sitionix.bff", "sitionix.notification");
        final HttpServletRequest request = this.getRequest(token);
        when(this.properties.getServiceId()).thenReturn("sitionix.auth");

        //when
        final Throwable thrown = catchThrowable(() -> this.verifier.verify(request));

        //then
        assertThat(thrown)
                .isInstanceOf(BadCredentialsException.class)
                .hasMessageContaining("Invalid internal authorization token");
        verify(this.properties).getServiceId();
    }

    @Test
    void givenTokenWithoutAudience_whenVerify_thenThrowsBadCredentialsException() {
        //given
        final String token = this.getTokenWithoutAudience("sitionix.bff");
        final HttpServletRequest request = this.getRequest(token);
        when(this.properties.getServiceId()).thenReturn("sitionix.auth");

        //when
        final Throwable thrown = catchThrowable(() -> this.verifier.verify(request));

        //then
        assertThat(thrown)
                .isInstanceOf(BadCredentialsException.class)
                .hasMessageContaining("Invalid internal authorization token");
        verify(this.properties).getServiceId();
    }

    @Test
    void givenTokenWithMatchingAudience_whenVerify_thenReturnsServiceIdentity() {
        //given
        final String token = this.getToken("sitionix.bff", "sitionix.auth");
        final HttpServletRequest request = this.getRequest(token);
        when(this.properties.getServiceId()).thenReturn("sitionix.auth");

        //when
        final ServiceIdentity identity = this.verifier.verify(request);

        //then
        assertThat(identity.serviceId()).isEqualTo("sitionix.bff");
        assertThat(identity.audience()).isEqualTo("sitionix.auth");
        verify(this.properties).getServiceId();
    }

    private ForgeSecurityServerProperties.DevJwt getDevJwt() {
        final ForgeSecurityServerProperties.DevJwt devJwt = new ForgeSecurityServerProperties.DevJwt();
        devJwt.setJwtSecret("test-internal-secret");
        devJwt.setIssuer("sitionix-internal");
        devJwt.setTtlSeconds(300);
        return devJwt;
    }

    private String getToken(final String subject, final String audience) {
        final Instant now = Instant.now();
        final Instant expiresAt = now.plusSeconds(600);
        return JWT.create()
                .withIssuer("sitionix-internal")
                .withSubject(subject)
                .withAudience(audience)
                .withIssuedAt(Date.from(now))
                .withExpiresAt(Date.from(expiresAt))
                .sign(Algorithm.HMAC256("test-internal-secret"));
    }

    private String getTokenWithoutAudience(final String subject) {
        final Instant now = Instant.now();
        final Instant expiresAt = now.plusSeconds(600);
        return JWT.create()
                .withIssuer("sitionix-internal")
                .withSubject(subject)
                .withIssuedAt(Date.from(now))
                .withExpiresAt(Date.from(expiresAt))
                .sign(Algorithm.HMAC256("test-internal-secret"));
    }

    private HttpServletRequest getRequest(final String token) {
        final HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getHeader("Authorization")).thenReturn("Bearer " + token);
        return request;
    }
}
