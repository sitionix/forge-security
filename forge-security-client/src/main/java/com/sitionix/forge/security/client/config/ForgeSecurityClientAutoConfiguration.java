package com.sitionix.forge.security.client.config;

import com.sitionix.forge.security.client.core.ForgeServiceAuthHeaderProvider;
import com.sitionix.forge.security.client.core.ServiceIdResolver;
import com.sitionix.forge.security.client.core.ServiceJwtIssuer;
import com.sitionix.forge.security.client.core.TargetAudienceResolver;
import com.sitionix.forge.security.client.web.DefaultTargetAudienceResolver;
import com.sitionix.forge.security.client.web.ForgeServiceAuthClientHttpRequestInterceptor;
import com.sitionix.forge.security.client.web.ForgeServiceAuthRestTemplateCustomizer;
import com.sitionix.forge.security.client.web.ForgeServiceAuthRestTemplatePostProcessor;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.ConfigurationPropertiesBinding;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.client.RestTemplateCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.web.client.RestTemplate;

import java.time.Clock;

@AutoConfiguration
@ConditionalOnClass(RestTemplate.class)
@ConditionalOnProperty(prefix = "forge.security.client", name = "enabled", havingValue = "true", matchIfMissing = true)
@EnableConfigurationProperties(ForgeSecurityClientProperties.class)
public class ForgeSecurityClientAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean(ForgeSecurityDevJwtConverter.class)
    @ConfigurationPropertiesBinding
    public Converter<String, ForgeSecurityClientProperties.DevJwt> forgeSecurityDevJwtConverter() {
        return new ForgeSecurityDevJwtConverter();
    }

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
            final ForgeSecurityClientProperties properties,
            final ForgeServiceAuthHeaderProvider headerProvider,
            final TargetAudienceResolver targetAudienceResolver) {
        return new ForgeServiceAuthClientHttpRequestInterceptor(properties, headerProvider, targetAudienceResolver);
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
    public ForgeSecurityClientValidator forgeSecurityClientValidator(final ForgeSecurityClientProperties properties,
                                                                     final org.springframework.core.env.Environment environment) {
        return new ForgeSecurityClientValidator(properties, environment);
    }
}
