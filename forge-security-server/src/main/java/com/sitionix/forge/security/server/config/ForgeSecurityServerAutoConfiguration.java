package com.sitionix.forge.security.server.config;

import com.sitionix.forge.security.server.core.DevJwtServiceIdentityVerifier;
import com.sitionix.forge.security.server.core.MtlsServiceIdentityVerifier;
import com.sitionix.forge.security.server.core.PolicyEnforcer;
import com.sitionix.forge.security.server.core.ServiceIdResolver;
import com.sitionix.forge.security.server.web.ForgeInternalAuthFilter;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;

@AutoConfiguration
@ConditionalOnClass({HttpSecurity.class, ForgeInternalAuthFilter.class})
@ConditionalOnProperty(prefix = "forge.security.server", name = "enabled", havingValue = "true", matchIfMissing = true)
@EnableConfigurationProperties(ForgeSecurityServerProperties.class)
public class ForgeSecurityServerAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public ServiceIdResolver forgeServiceIdResolver(final ForgeSecurityServerProperties properties) {
        return new ServiceIdResolver(properties);
    }

    @Bean
    public DevJwtServiceIdentityVerifier devJwtServiceIdentityVerifier(final ForgeSecurityServerProperties properties,
                                                                       final ServiceIdResolver serviceIdResolver) {
        return new DevJwtServiceIdentityVerifier(properties, serviceIdResolver);
    }

    @Bean
    public MtlsServiceIdentityVerifier mtlsServiceIdentityVerifier(final ServiceIdResolver serviceIdResolver) {
        return new MtlsServiceIdentityVerifier(serviceIdResolver);
    }

    @Bean
    public PolicyEnforcer forgeSecurityPolicyEnforcer(final ForgeSecurityServerProperties properties) {
        return new PolicyEnforcer(properties);
    }

    @Bean
    public ForgeInternalAuthFilter forgeInternalAuthFilter(final ForgeSecurityServerProperties properties,
                                                           final DevJwtServiceIdentityVerifier devJwtVerifier,
                                                           final MtlsServiceIdentityVerifier mtlsVerifier,
                                                           final PolicyEnforcer policyEnforcer) {
        return new ForgeInternalAuthFilter(properties, devJwtVerifier, mtlsVerifier, policyEnforcer);
    }

    @Bean
    public FilterRegistrationBean<ForgeInternalAuthFilter> forgeInternalAuthFilterRegistration(
            final ForgeInternalAuthFilter forgeInternalAuthFilter) {
        final FilterRegistrationBean<ForgeInternalAuthFilter> registration =
                new FilterRegistrationBean<>(forgeInternalAuthFilter);
        registration.setEnabled(false);
        return registration;
    }

    @Bean
    @ConditionalOnMissingBean(SecurityFilterChain.class)
    public SecurityFilterChain forgeSecurityFilterChain(final HttpSecurity http,
                                                        final ForgeInternalAuthFilter forgeInternalAuthFilter,
                                                        final ObjectProvider<AuthenticationEntryPoint> entryPointProvider,
                                                        final ObjectProvider<AccessDeniedHandler> accessDeniedHandlerProvider)
            throws Exception {
        final AuthenticationEntryPoint entryPoint = entryPointProvider.getIfAvailable();
        final AccessDeniedHandler accessDeniedHandler = accessDeniedHandlerProvider.getIfAvailable();

        http.csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
                .addFilterBefore(forgeInternalAuthFilter, AuthorizationFilter.class);

        if (entryPoint != null || accessDeniedHandler != null) {
            http.exceptionHandling(exceptionHandling -> {
                if (entryPoint != null) {
                    exceptionHandling.authenticationEntryPoint(entryPoint);
                }
                if (accessDeniedHandler != null) {
                    exceptionHandling.accessDeniedHandler(accessDeniedHandler);
                }
            });
        }
        return http.build();
    }

    @Bean
    public ForgeSecurityServerValidator forgeSecurityServerValidator(final ForgeSecurityServerProperties properties,
                                                                     final org.springframework.core.env.Environment environment) {
        return new ForgeSecurityServerValidator(properties, environment);
    }
}
