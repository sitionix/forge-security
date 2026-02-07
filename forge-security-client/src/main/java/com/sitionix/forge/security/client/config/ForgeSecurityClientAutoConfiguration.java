package com.sitionix.forge.security.client.config;

import com.sitionix.forge.security.client.core.ForgeServiceAuthHeaderProvider;
import com.sitionix.forge.security.client.core.ServiceIdResolver;
import com.sitionix.forge.security.client.core.ServiceJwtIssuer;
import com.sitionix.forge.security.client.core.TargetAudienceResolver;
import com.sitionix.forge.security.client.web.DefaultTargetAudienceResolver;
import com.sitionix.forge.security.client.web.ForgeServiceAuthClientHttpRequestInterceptor;
import com.sitionix.forge.security.client.web.ForgeServiceAuthRestTemplateCustomizer;
import com.sitionix.forge.security.client.web.ForgeServiceAuthRestTemplatePostProcessor;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.client.RestTemplateCustomizer;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.util.ClassUtils;
import org.springframework.web.client.RestTemplate;

import java.time.Clock;

@AutoConfiguration
@ConditionalOnClass(RestTemplate.class)
@EnableConfigurationProperties(ForgeSecurityClientProperties.class)
public class ForgeSecurityClientAutoConfiguration {

    private static final String CURRENT_FORGE_USER_CLASS =
            "com.sitionix.forge.security.userjwt.web.CurrentForgeUser";

    @Bean
    @ConditionalOnMissingBean
    public Clock forgeSecurityClock() {
        return Clock.systemUTC();
    }

    @Bean
    public ServiceJwtIssuer forgeServiceJwtIssuer(final ForgeSecurityClientProperties properties,
                                                  final Clock clock) {
        return new ServiceJwtIssuer(properties, clock);
    }

    @Bean
    public ForgeServiceAuthHeaderProvider forgeServiceAuthHeaderProvider(final ForgeSecurityClientProperties properties,
                                                                         final ServiceJwtIssuer serviceJwtIssuer) {
        return new ForgeServiceAuthHeaderProvider(properties, serviceJwtIssuer);
    }

    @Bean
    @ConditionalOnMissingBean
    public ServiceIdResolver forgeServiceIdResolver(final ForgeSecurityClientProperties properties) {
        return new ServiceIdResolver(properties);
    }

    @Bean
    @ConditionalOnMissingBean
    public TargetAudienceResolver forgeTargetAudienceResolver(final ServiceIdResolver serviceIdResolver) {
        return new DefaultTargetAudienceResolver(serviceIdResolver);
    }

    @Bean
    public ClientHttpRequestInterceptor forgeServiceAuthClientHttpRequestInterceptor(
            final ForgeServiceAuthHeaderProvider headerProvider,
            final TargetAudienceResolver targetAudienceResolver,
            final ApplicationContext applicationContext) {
        final ObjectProvider<?> currentForgeUserProvider = this.resolveCurrentForgeUserProvider(applicationContext);
        return new ForgeServiceAuthClientHttpRequestInterceptor(headerProvider, targetAudienceResolver,
                currentForgeUserProvider);
    }

    @Bean
    public RestTemplateCustomizer forgeServiceAuthRestTemplateCustomizer(
            final ClientHttpRequestInterceptor forgeServiceAuthClientHttpRequestInterceptor) {
        return new ForgeServiceAuthRestTemplateCustomizer(forgeServiceAuthClientHttpRequestInterceptor);
    }

    @Bean
    public ForgeServiceAuthRestTemplatePostProcessor forgeServiceAuthRestTemplatePostProcessor(
            final ClientHttpRequestInterceptor forgeServiceAuthClientHttpRequestInterceptor) {
        return new ForgeServiceAuthRestTemplatePostProcessor(forgeServiceAuthClientHttpRequestInterceptor);
    }

    @Bean
    public ForgeSecurityClientValidator forgeSecurityClientValidator(final ForgeSecurityClientProperties properties) {
        return new ForgeSecurityClientValidator(properties);
    }

    private ObjectProvider<?> resolveCurrentForgeUserProvider(final ApplicationContext applicationContext) {
        if (applicationContext == null) {
            return null;
        }
        final ClassLoader classLoader = applicationContext.getClassLoader();
        if (!ClassUtils.isPresent(CURRENT_FORGE_USER_CLASS, classLoader)) {
            return null;
        }
        try {
            final Class<?> userProviderClass = Class.forName(CURRENT_FORGE_USER_CLASS, false, classLoader);
            return applicationContext.getBeanProvider(userProviderClass);
        } catch (final ClassNotFoundException ex) {
            return null;
        }
    }
}
