package com.sitionix.forge.security.client.web;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.web.client.RestTemplate;

public class ForgeServiceAuthRestTemplatePostProcessor implements BeanPostProcessor {

    private final ClientHttpRequestInterceptor interceptor;

    public ForgeServiceAuthRestTemplatePostProcessor(final ClientHttpRequestInterceptor interceptor) {
        this.interceptor = interceptor;
    }

    @Override
    public Object postProcessAfterInitialization(final Object bean, final String beanName) throws BeansException {
        if (bean instanceof RestTemplate restTemplate) {
            if (!restTemplate.getInterceptors().contains(this.interceptor)) {
                restTemplate.getInterceptors().add(this.interceptor);
            }
        }
        return bean;
    }
}
