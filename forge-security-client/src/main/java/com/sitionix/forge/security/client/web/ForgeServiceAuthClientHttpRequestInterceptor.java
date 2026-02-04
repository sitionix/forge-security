package com.sitionix.forge.security.client.web;

import com.sitionix.forge.security.client.core.ForgeServiceAuthHeaderProvider;
import com.sitionix.forge.security.client.core.TargetAudienceResolver;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.util.StringUtils;

import java.io.IOException;

public class ForgeServiceAuthClientHttpRequestInterceptor implements ClientHttpRequestInterceptor {

    private final ForgeServiceAuthHeaderProvider headerProvider;
    private final TargetAudienceResolver targetAudienceResolver;

    public ForgeServiceAuthClientHttpRequestInterceptor(final ForgeServiceAuthHeaderProvider headerProvider,
                                                        final TargetAudienceResolver targetAudienceResolver) {
        this.headerProvider = headerProvider;
        this.targetAudienceResolver = targetAudienceResolver;
    }

    @Override
    public ClientHttpResponse intercept(final HttpRequest request,
                                        final byte[] body,
                                        final ClientHttpRequestExecution execution) throws IOException {
        final HttpHeaders headers = request.getHeaders();
        if (headers.containsKey(HttpHeaders.AUTHORIZATION)) {
            return execution.execute(request, body);
        }
        final String audience = this.targetAudienceResolver.resolve(request);
        final String authorizationValue = this.headerProvider.getAuthorizationValue(audience);
        if (StringUtils.hasText(authorizationValue)) {
            headers.set(HttpHeaders.AUTHORIZATION, authorizationValue);
        }
        return execution.execute(request, body);
    }
}
