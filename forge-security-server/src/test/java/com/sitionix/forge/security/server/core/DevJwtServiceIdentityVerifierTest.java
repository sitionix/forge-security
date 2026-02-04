package com.sitionix.forge.security.server.core;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.sitionix.forge.security.server.config.ForgeSecurityMode;
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

    @Mock
    private ServiceIdResolver serviceIdResolver;

    private DevJwtServiceIdentityVerifier verifier;

    @BeforeEach
    void setUp() {
        final ForgeSecurityServerProperties.DevJwt devJwt = this.getDevJwt();
        when(this.properties.getMode()).thenReturn(ForgeSecurityMode.DEV_JWT);
        when(this.properties.getDev()).thenReturn(devJwt);
        this.verifier = new DevJwtServiceIdentityVerifier(this.properties, this.serviceIdResolver);
        this.verifier.init();
    }

    @AfterEach
    void tearDown() {
        verify(this.properties).getMode();
        verify(this.properties).getDev();
        verifyNoMoreInteractions(this.properties, this.serviceIdResolver);
    }

    @Test
    void givenTokenWithHostAudience_whenVerify_thenThrowsBadCredentialsException() {
        //given
        final String token = this.getToken("sitionix.bff", "auth-service");
        final HttpServletRequest request = this.getRequest(token);
        when(this.properties.getAcceptedAudiences()).thenReturn(List.of("sitionix.auth"));
        when(this.serviceIdResolver.isServiceId("sitionix.bff")).thenReturn(true);

        //when
        final Throwable thrown = catchThrowable(() -> this.verifier.verify(request));

        //then
        assertThat(thrown)
                .isInstanceOf(BadCredentialsException.class)
                .hasMessageContaining("Invalid internal authorization token");
        verify(this.properties).getAcceptedAudiences();
        verify(this.serviceIdResolver).isServiceId("sitionix.bff");
    }

    @Test
    void givenTokenWithHostSubject_whenVerify_thenThrowsBadCredentialsException() {
        //given
        final String token = this.getToken("bff-service", "sitionix.auth");
        final HttpServletRequest request = this.getRequest(token);
        when(this.serviceIdResolver.isServiceId("bff-service")).thenReturn(false);

        //when
        final Throwable thrown = catchThrowable(() -> this.verifier.verify(request));

        //then
        assertThat(thrown)
                .isInstanceOf(BadCredentialsException.class)
                .hasMessageContaining("Invalid internal authorization token");
        verify(this.serviceIdResolver).isServiceId("bff-service");
    }

    @Test
    void givenTokenWithWrongAudience_whenVerify_thenThrowsBadCredentialsException() {
        //given
        final String token = this.getToken("sitionix.bff", "sitionix.notification");
        final HttpServletRequest request = this.getRequest(token);
        when(this.properties.getAcceptedAudiences()).thenReturn(List.of("sitionix.auth"));
        when(this.serviceIdResolver.isServiceId("sitionix.bff")).thenReturn(true);

        //when
        final Throwable thrown = catchThrowable(() -> this.verifier.verify(request));

        //then
        assertThat(thrown)
                .isInstanceOf(BadCredentialsException.class)
                .hasMessageContaining("Invalid internal authorization token");
        verify(this.properties).getAcceptedAudiences();
        verify(this.serviceIdResolver).isServiceId("sitionix.bff");
    }

    @Test
    void givenTokenWithLogicalIds_whenVerify_thenReturnsServiceIdentity() {
        //given
        final String token = this.getToken("sitionix.bff", "sitionix.auth");
        final HttpServletRequest request = this.getRequest(token);
        when(this.properties.getAcceptedAudiences()).thenReturn(List.of("sitionix.auth"));
        when(this.serviceIdResolver.isServiceId("sitionix.bff")).thenReturn(true);
        when(this.serviceIdResolver.isServiceId("sitionix.auth")).thenReturn(true);

        //when
        final ServiceIdentity identity = this.verifier.verify(request);

        //then
        assertThat(identity.serviceName()).isEqualTo("sitionix.bff");
        assertThat(identity.audience()).isEqualTo("sitionix.auth");
        verify(this.properties).getAcceptedAudiences();
        verify(this.serviceIdResolver).isServiceId("sitionix.bff");
        verify(this.serviceIdResolver).isServiceId("sitionix.auth");
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

    private HttpServletRequest getRequest(final String token) {
        final HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getHeader("Authorization")).thenReturn("Bearer " + token);
        return request;
    }
}
