package com.sitionix.forge.security.userjwt.web;

import com.sitionix.forge.security.userjwt.core.ForgeUser;
import com.sitionix.forge.security.userjwt.core.UserJwtVerifier;
import com.sitionix.forge.security.userjwt.core.UserJwtVerificationException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import jakarta.servlet.FilterChain;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ForgeUserJwtFilterTest {

    @Mock
    private UserJwtVerifier userJwtVerifier;

    @Mock
    private UserJwtErrorResponseWriter errorResponseWriter;

    private ForgeUserJwtFilter subject;

    @BeforeEach
    void setUp() {
        this.subject = new ForgeUserJwtFilter(this.userJwtVerifier, this.errorResponseWriter);
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
        verifyNoMoreInteractions(this.userJwtVerifier, this.errorResponseWriter);
    }

    @Test
    void givenNoAuthorizationHeader_whenDoFilter_thenContinues() throws Exception {
        //given
        final MockHttpServletRequest request = this.getRequestWithoutAuthorization();
        final MockHttpServletResponse response = this.getResponse();
        final FilterChain chain = mock(FilterChain.class);

        //when
        this.subject.doFilter(request, response, chain);

        //then
        verify(chain).doFilter(request, response);
        verifyNoMoreInteractions(chain);
    }

    @Test
    void givenServiceJwt_whenDoFilter_thenContinues() throws Exception {
        //given
        final String token = "service.jwt.token";
        final MockHttpServletRequest request = this.getRequestWithBearer(token);
        final MockHttpServletResponse response = this.getResponse();
        final FilterChain chain = mock(FilterChain.class);
        when(this.userJwtVerifier.looksLikeUserJwt(token)).thenReturn(false);

        //when
        this.subject.doFilter(request, response, chain);

        //then
        verify(chain).doFilter(request, response);
        verify(this.userJwtVerifier).looksLikeUserJwt(token);
        verifyNoMoreInteractions(chain);
    }

    @Test
    void givenBearerGarbage_whenDoFilter_thenContinues() throws Exception {
        //given
        final String token = "not-a-jwt";
        final MockHttpServletRequest request = this.getRequestWithBearer(token);
        final MockHttpServletResponse response = this.getResponse();
        final FilterChain chain = mock(FilterChain.class);
        when(this.userJwtVerifier.looksLikeUserJwt(token)).thenReturn(false);

        //when
        this.subject.doFilter(request, response, chain);

        //then
        verify(chain).doFilter(request, response);
        verify(this.userJwtVerifier).looksLikeUserJwt(token);
        verifyNoMoreInteractions(chain);
    }

    @Test
    void givenValidUserJwt_whenDoFilter_thenAuthenticatesAndContinues() throws Exception {
        //given
        final String token = "valid.user.jwt";
        final MockHttpServletRequest request = this.getRequestWithBearer(token);
        final MockHttpServletResponse response = this.getResponse();
        final FilterChain chain = mock(FilterChain.class);
        final ForgeUser user = mock(ForgeUser.class);
        when(this.userJwtVerifier.looksLikeUserJwt(token)).thenReturn(true);
        when(this.userJwtVerifier.validateUserJwt(token)).thenReturn(user);

        //when
        this.subject.doFilter(request, response, chain);

        //then
        verify(chain).doFilter(request, response);
        final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        assertThat(authentication).isNotNull();
        assertThat(authentication.getPrincipal()).isEqualTo(user);
        verify(this.userJwtVerifier).looksLikeUserJwt(token);
        verify(this.userJwtVerifier).validateUserJwt(token);
        verifyNoMoreInteractions(chain);
    }

    @Test
    void givenInvalidUserJwt_whenDoFilter_thenReturnsUnauthorized() throws Exception {
        //given
        final String token = "invalid.user.jwt";
        final MockHttpServletRequest request = this.getRequestWithBearer(token);
        final MockHttpServletResponse response = this.getResponse();
        final FilterChain chain = mock(FilterChain.class);
        when(this.userJwtVerifier.looksLikeUserJwt(token)).thenReturn(true);
        when(this.userJwtVerifier.validateUserJwt(token))
                .thenThrow(new UserJwtVerificationException("Invalid user token"));

        //when
        this.subject.doFilter(request, response, chain);

        //then
        verify(this.userJwtVerifier).looksLikeUserJwt(token);
        verify(this.userJwtVerifier).validateUserJwt(token);
        verify(this.errorResponseWriter)
                .write(response, 401, "unauthorized", "Invalid token");
        verifyNoMoreInteractions(chain);
    }

    @Test
    void givenExpiredUserJwt_whenDoFilter_thenReturnsUnauthorized() throws Exception {
        //given
        final String token = "expired.user.jwt";
        final MockHttpServletRequest request = this.getRequestWithBearer(token);
        final MockHttpServletResponse response = this.getResponse();
        final FilterChain chain = mock(FilterChain.class);
        when(this.userJwtVerifier.looksLikeUserJwt(token)).thenReturn(true);
        when(this.userJwtVerifier.validateUserJwt(token))
                .thenThrow(new UserJwtVerificationException("Expired user token"));

        //when
        this.subject.doFilter(request, response, chain);

        //then
        verify(this.userJwtVerifier).looksLikeUserJwt(token);
        verify(this.userJwtVerifier).validateUserJwt(token);
        verify(this.errorResponseWriter)
                .write(response, 401, "unauthorized", "Invalid token");
        verifyNoMoreInteractions(chain);
    }

    private MockHttpServletRequest getRequestWithBearer(final String token) {
        final MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Bearer " + token);
        return request;
    }

    private MockHttpServletRequest getRequestWithoutAuthorization() {
        return new MockHttpServletRequest();
    }

    private MockHttpServletResponse getResponse() {
        return new MockHttpServletResponse();
    }
}
