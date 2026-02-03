package com.sitionix.forge.security.client.web;

import org.springframework.boot.web.client.RestTemplateCustomizer;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.web.client.RestTemplate;

public class ForgeServiceAuthRestTemplateCustomizer implements RestTemplateCustomizer {

    private final ClientHttpRequestInterceptor interceptor;

    public ForgeServiceAuthRestTemplateCustomizer(final ClientHttpRequestInterceptor interceptor) {
        this.interceptor = interceptor;
    }

    @Override
    public void customize(final RestTemplate restTemplate) {
        if (restTemplate == null) {
            return;
        }
        if (!restTemplate.getInterceptors().contains(this.interceptor)) {
            restTemplate.getInterceptors().add(this.interceptor);
        }
    }
}
