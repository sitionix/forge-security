package com.sitionix.forge.security.client.web;

import com.sitionix.forge.security.client.core.ForgeServiceAuthHeaderProvider;
import com.sitionix.forge.security.client.core.TargetAudienceResolver;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.lang.reflect.Method;
public class ForgeServiceAuthClientHttpRequestInterceptor implements ClientHttpRequestInterceptor {

    private static final String FORGE_USER_SUB_HEADER = "X-Forge-User-Sub";
    private static final String CURRENT_USER_METHOD = "currentUser";
    private static final String SUBJECT_METHOD = "getSubject";

    private final ForgeServiceAuthHeaderProvider headerProvider;
    private final TargetAudienceResolver targetAudienceResolver;
    private final ObjectProvider<?> currentForgeUserProvider;

    public ForgeServiceAuthClientHttpRequestInterceptor(final ForgeServiceAuthHeaderProvider headerProvider,
                                                        final TargetAudienceResolver targetAudienceResolver,
                                                        final ObjectProvider<?> currentForgeUserProvider) {
        this.headerProvider = headerProvider;
        this.targetAudienceResolver = targetAudienceResolver;
        this.currentForgeUserProvider = currentForgeUserProvider;
    }

    @Override
    public ClientHttpResponse intercept(final HttpRequest request,
                                        final byte[] body,
                                        final ClientHttpRequestExecution execution) throws IOException {
        final HttpHeaders headers = request.getHeaders();
        if (headers.containsKey(HttpHeaders.AUTHORIZATION)) {
            this.applyForgeUserHeader(headers);
            return execution.execute(request, body);
        }
        final String audience = this.targetAudienceResolver.resolve(request);
        final String authorizationValue = this.headerProvider.getAuthorizationValue(audience);
        if (StringUtils.hasText(authorizationValue)) {
            headers.set(HttpHeaders.AUTHORIZATION, authorizationValue);
        }
        this.applyForgeUserHeader(headers);
        return execution.execute(request, body);
    }

    private void applyForgeUserHeader(final HttpHeaders headers) {
        if (headers.containsKey(FORGE_USER_SUB_HEADER)) {
            return;
        }
        final String subject = this.resolveForgeUserSubject();
        if (StringUtils.hasText(subject)) {
            headers.set(FORGE_USER_SUB_HEADER, subject);
        }
    }

    private String resolveForgeUserSubject() {
        if (this.currentForgeUserProvider == null) {
            return null;
        }
        final Object currentForgeUser = this.currentForgeUserProvider.getIfAvailable();
        if (currentForgeUser == null) {
            return null;
        }
        try {
            final Method currentUser = currentForgeUser.getClass().getMethod(CURRENT_USER_METHOD);
            final Object forgeUser = currentUser.invoke(currentForgeUser);
            if (forgeUser == null) {
                return null;
            }
            final Method subjectMethod = forgeUser.getClass().getMethod(SUBJECT_METHOD);
            final Object subject = subjectMethod.invoke(forgeUser);
            if (subject instanceof String value && StringUtils.hasText(value)) {
                return value;
            }
        } catch (final Exception ignored) {
            return null;
        }
        return null;
    }
}
