package com.sitionix.forge.security.client.web;

import com.sitionix.forge.security.client.core.ForgeServiceAuthHeaderProvider;
import com.sitionix.forge.security.client.core.TargetAudienceResolver;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.client.MockClientHttpRequest;
import org.springframework.mock.http.client.MockClientHttpResponse;

import java.net.URI;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ForgeServiceAuthClientHttpRequestInterceptorTest {

    private ForgeServiceAuthClientHttpRequestInterceptor interceptor;

    @Mock
    private ForgeServiceAuthHeaderProvider headerProvider;

    @Mock
    private TargetAudienceResolver targetAudienceResolver;

    @Mock
    private ObjectProvider<?> currentForgeUserProvider;

    @Mock
    private ObjectProvider<?> forgeUserClientProvider;

    @BeforeEach
    void setUp() {
        this.interceptor = new ForgeServiceAuthClientHttpRequestInterceptor(this.headerProvider,
                this.targetAudienceResolver,
                this.currentForgeUserProvider,
                this.forgeUserClientProvider);
    }

    @AfterEach
    void tearDown() {
        verifyNoMoreInteractions(this.headerProvider,
                this.targetAudienceResolver,
                this.currentForgeUserProvider,
                this.forgeUserClientProvider);
    }

    @Test
    void givenForgeUser_whenIntercept_thenAddsUserSubHeader() throws Exception {
        //given
        final MockClientHttpRequest request = new MockClientHttpRequest();
        request.setURI(URI.create("http://localhost/authsox/api/v1/auth/email/verify/resend"));
        final DummyCurrentForgeUser currentForgeUser = new DummyCurrentForgeUser("user-123");

        when(this.targetAudienceResolver.resolve(request))
                .thenReturn("sitionixAuth");
        when(this.headerProvider.getAuthorizationValue("sitionixAuth"))
                .thenReturn("Bearer s2s-token");
        when(this.currentForgeUserProvider.getIfAvailable())
                .thenReturn(currentForgeUser);

        //when
        this.interceptor.intercept(request, new byte[0], (req, body) ->
                new MockClientHttpResponse(new byte[0], HttpStatus.OK));

        //then
        assertThat(request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION))
                .isEqualTo("Bearer s2s-token");
        assertThat(request.getHeaders().getFirst("X-Forge-User-Sub"))
                .isEqualTo("user-123");

        verify(this.targetAudienceResolver).resolve(request);
        verify(this.headerProvider).getAuthorizationValue("sitionixAuth");
        verify(this.currentForgeUserProvider).getIfAvailable();
        verifyNoInteractions(this.forgeUserClientProvider);
    }

    @Test
    void givenMissingForgeUser_whenIntercept_thenDoesNotAddUserSubHeader() throws Exception {
        //given
        final MockClientHttpRequest request = new MockClientHttpRequest();
        request.setURI(URI.create("http://localhost/authsox/api/v1/auth/email/verify/resend"));

        when(this.targetAudienceResolver.resolve(request))
                .thenReturn("sitionixAuth");
        when(this.headerProvider.getAuthorizationValue("sitionixAuth"))
                .thenReturn("Bearer s2s-token");
        when(this.currentForgeUserProvider.getIfAvailable())
                .thenReturn(null);
        when(this.forgeUserClientProvider.getIfAvailable())
                .thenReturn(null);

        //when
        this.interceptor.intercept(request, new byte[0], (req, body) ->
                new MockClientHttpResponse(new byte[0], HttpStatus.OK));

        //then
        assertThat(request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION))
                .isEqualTo("Bearer s2s-token");
        assertThat(request.getHeaders().containsKey("X-Forge-User-Sub"))
                .isFalse();

        verify(this.targetAudienceResolver).resolve(request);
        verify(this.headerProvider).getAuthorizationValue("sitionixAuth");
        verify(this.currentForgeUserProvider).getIfAvailable();
        verify(this.forgeUserClientProvider).getIfAvailable();
    }

    @Test
    void givenMissingCurrentForgeUserAndPresentForgeUserClient_whenIntercept_thenAddsUserSubHeaderFromUserClient() throws Exception {
        //given
        final MockClientHttpRequest request = new MockClientHttpRequest();
        request.setURI(URI.create("http://localhost/wagssox/api/v1/sites"));
        final DummyForgeUserClient forgeUserClient = new DummyForgeUserClient(321L);

        when(this.targetAudienceResolver.resolve(request))
                .thenReturn("sitionixWorkspace");
        when(this.headerProvider.getAuthorizationValue("sitionixWorkspace"))
                .thenReturn("Bearer s2s-token");
        when(this.currentForgeUserProvider.getIfAvailable())
                .thenReturn(null);
        when(this.forgeUserClientProvider.getIfAvailable())
                .thenReturn(forgeUserClient);

        //when
        this.interceptor.intercept(request, new byte[0], (req, body) ->
                new MockClientHttpResponse(new byte[0], HttpStatus.OK));

        //then
        assertThat(request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION))
                .isEqualTo("Bearer s2s-token");
        assertThat(request.getHeaders().getFirst("X-Forge-User-Sub"))
                .isEqualTo("321");

        verify(this.targetAudienceResolver).resolve(request);
        verify(this.headerProvider).getAuthorizationValue("sitionixWorkspace");
        verify(this.currentForgeUserProvider).getIfAvailable();
        verify(this.forgeUserClientProvider).getIfAvailable();
    }

    private static final class DummyCurrentForgeUser {

        private final String subject;

        private DummyCurrentForgeUser(final String subject) {
            this.subject = subject;
        }

        @SuppressWarnings("unused")
        public DummyForgeUser currentUser() {
            return new DummyForgeUser(this.subject);
        }
    }

    private static final class DummyForgeUser {

        private final String subject;

        private DummyForgeUser(final String subject) {
            this.subject = subject;
        }

        @SuppressWarnings("unused")
        public String getSubject() {
            return this.subject;
        }
    }

    private static final class DummyForgeUserClient {

        private final Long userId;

        private DummyForgeUserClient(final Long userId) {
            this.userId = userId;
        }

        @SuppressWarnings("unused")
        public Long getUserId() {
            return this.userId;
        }
    }
}
